"""G5: the owner's approval flow (owner side only; no AI-facing tool can reach this).

What the owner sees and what counts as approval:
- The text shown comes from the ROOT installer (``broker.challenge``), computed from the stored plan.
  This module only relays it; the AI-facing service never produces or edits it.
- Approve and Deny are two separate, explicit actions. Each has its own root challenge, and the
  Auth0 sign-in for a choice carries that choice's nonce, so a sign-in for "deny" can never be
  used as "approve", and a plain login without a challenge is never approval.
- The sign-in uses the authorization-code flow with PKCE, a single-use ``state``, and
  ``prompt=login`` + ``max_age=0`` so the owner authenticates freshly for this decision.
- The page's form carries a per-view CSRF token; a choice can be made once per view.
- Request state moves only through ``RequestStore.transition`` (pending -> approved|denied ->
  running -> done|failed|needs_owner_intervention), compare-and-set, so a double click or a
  replayed callback can't decide twice. A denial never calls the install path.

The HTTP page, the Auth0 token exchange and the broker call are injected, so this logic is
tested without a network (see tests/test_approval.py).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time

from .requests import RequestError

VIEW_LIFETIME = 600
MAX_VIEWS = 64


class ApprovalError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def pkce_challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


class ApprovalFlow:
    """``broker``: object with challenge(payload, decision), install/rollback/deny(payload, proof, challenge).
    ``exchange``: callable(code, code_verifier) -> Auth0 ID token string.
    ``authorize``: dict(endpoint, client_id, redirect_uri)."""

    def __init__(self, *, store, broker, exchange, authorize, clock=time.time):
        if (type(authorize) is not dict or type(authorize.get("endpoint")) is not str
                or not authorize["endpoint"].startswith("https://")
                or type(authorize.get("redirect_uri")) is not str
                or not authorize["redirect_uri"].startswith(("https://", "http://127.0.0.1"))
                or type(authorize.get("client_id")) is not str or not authorize["client_id"]):
            raise ValueError("authorize needs an https endpoint, a client_id and an https (or loopback) redirect_uri")
        self.store, self.broker, self.exchange, self.authorize = store, broker, exchange, dict(authorize)
        self.clock, self._lock = clock, threading.Lock()
        self._views, self._states = {}, {}

    def _sweep(self):
        now = self.clock()
        for table in (self._views, self._states):
            for key in [k for k, v in table.items() if v["expires"] <= now]:
                del table[key]

    # -- 1. show the request ------------------------------------------------------------------
    def page(self, request_id):
        """What to render: the root-written summary and two explicit choices. Only for a pending request."""
        try:
            payload = self.store.payload(request_id)
            receipt = None if payload is None else self.store.status(
                request_id, owner=payload.get("owner"), device=payload.get("device"))
        except RequestError:
            raise ApprovalError("unknown_request") from None
        if receipt is None or receipt["state"] != "pending":
            raise ApprovalError("request_not_pending")
        try:
            approve = self.broker.challenge(payload, "approve")
            deny = self.broker.challenge(payload, "deny")
        except Exception as error:
            raise ApprovalError("installer_refused_%s" % getattr(error, "code", "unavailable")) from None
        view, csrf = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        with self._lock:
            self._sweep()
            if len(self._views) >= MAX_VIEWS:
                raise ApprovalError("too_many_open_approval_pages")
            self._views[view] = {"request_id": request_id, "csrf": csrf, "challenges": {"approve": approve, "deny": deny},
                                 "used": False, "expires": self.clock() + VIEW_LIFETIME}
        return {"view": view, "csrf": csrf, "request_id": request_id, "kind": payload.get("kind", "install"),
                "summary": list(approve["summary"]), "choices": ["approve", "deny"],
                "expires_in": VIEW_LIFETIME}

    # -- 2. the owner picks Approve or Deny: start a fresh Auth0 sign-in for exactly that choice --------
    def choose(self, view, csrf, decision):
        if decision not in ("approve", "deny"):
            raise ApprovalError("invalid_decision")
        with self._lock:
            self._sweep()
            item = self._views.get(view if type(view) is str else "")
            if item is None:
                raise ApprovalError("page_expired")
            if type(csrf) is not str or not hmac.compare_digest(csrf, item["csrf"]):
                raise ApprovalError("csrf_check_failed")
            if item["used"]:
                raise ApprovalError("already_chosen")
            item["used"] = True
            state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
            challenge = item["challenges"][decision]
            self._states[state] = {"request_id": item["request_id"], "decision": decision, "verifier": verifier,
                                   "challenge": challenge["challenge"], "expires": self.clock() + VIEW_LIFETIME}
        return {"url": self.authorize["endpoint"],
                "params": {"response_type": "code", "client_id": self.authorize["client_id"],
                           "redirect_uri": self.authorize["redirect_uri"], "scope": "openid", "state": state,
                           "nonce": challenge["nonce"], "code_challenge": pkce_challenge(verifier),
                           "code_challenge_method": "S256", "prompt": "login", "max_age": "0"}}

    # -- 3. Auth0 sends the owner back: record the decision, then act on it exactly once ---------------
    def finish(self, state, code):
        with self._lock:
            self._sweep()
            item = self._states.pop(state if type(state) is str else "", None)      # single use
        if item is None:
            raise ApprovalError("unknown_or_used_state")
        rid, decision = item["request_id"], item["decision"]
        payload = self.store.payload(rid)
        if payload is None:
            raise ApprovalError("unknown_request")
        try:
            id_token = self.exchange(code, item["verifier"])
        except Exception:
            raise ApprovalError("sign_in_failed") from None
        # One decision per request: the compare-and-set is what stops a double decision.
        target = "approved" if decision == "approve" else "denied"
        if not self.store.transition(rid, "pending", target):
            raise ApprovalError("request_not_pending")
        if decision == "deny":
            try:
                result = self.broker.deny(payload, id_token, item["challenge"])
            except Exception as error:
                # The owner said no. Even if recording the denial at the installer failed, nothing runs.
                return {"state": "denied", "recorded_by_installer": False, "note": getattr(error, "code", "unavailable")}
            return {"state": "denied", "recorded_by_installer": bool(result.get("ok"))}
        self.store.transition(rid, "approved", "running")
        method = self.broker.rollback if payload.get("kind") == "rollback" else self.broker.install
        try:
            result = method(payload, id_token, item["challenge"])
        except Exception as error:
            code_ = getattr(error, "code", "installer_unavailable")
            # Refused before anything changed (bad proof, expired, drift...): failed, nothing ran.
            result = {"ok": False, "stopped": code_, "changed_anything": False}
        if result.get("needs_owner_intervention"):
            state_ = "needs_owner_intervention"
        else:
            state_ = "done" if result.get("ok") else "failed"
        self.store.transition(rid, "running", state_, result=result)
        return {"state": state_, "ok": bool(result.get("ok"))}

    def recover(self):
        """Call once at startup: runs interrupted by a crash are marked for the owner, never retried."""
        return self.store.recover_interrupted()
