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
from concurrent.futures import ThreadPoolExecutor

from .broker.proof import summary_hash
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

    def __init__(self, *, store, broker, exchange, authorize, clock=time.time, background=False):
        if (type(authorize) is not dict or type(authorize.get("endpoint")) is not str
                or not authorize["endpoint"].startswith("https://")
                or type(authorize.get("redirect_uri")) is not str
                or not authorize["redirect_uri"].startswith(("https://", "http://127.0.0.1"))
                or type(authorize.get("client_id")) is not str or not authorize["client_id"]):
            raise ValueError("authorize needs an https endpoint, a client_id and an https (or loopback) redirect_uri")
        self.store, self.broker, self.exchange, self.authorize = store, broker, exchange, dict(authorize)
        self.clock, self._lock = clock, threading.Lock()
        # background=True: the install runs on ONE worker thread, so the approval page and its other requests
        # stay responsive during a long install. Progress is the request's durable state (running -> done...).
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="stynpilot-approve") if background else None
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
        for challenge in (approve, deny):                       # the text must be exactly what the root produced
            if summary_hash(list(challenge.get("summary", []))) != challenge.get("summary_sha256"):
                raise ApprovalError("summary_altered_in_transit")
        if approve["summary"] != deny["summary"]:
            raise ApprovalError("summary_altered_in_transit")
        view, csrf = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        with self._lock:
            self._sweep()
            if len(self._views) >= MAX_VIEWS:
                raise ApprovalError("too_many_open_approval_pages")
            self._views[view] = {"request_id": request_id, "csrf": csrf, "challenges": {"approve": approve, "deny": deny},
                                 "used": False, "expires": self.clock() + VIEW_LIFETIME}
        return {"view": view, "csrf": csrf, "request_id": request_id, "kind": payload.get("kind", "install"),
                "summary": list(approve["summary"]), "summary_sha256": approve["summary_sha256"],
                "fingerprint": request_id[:12], "choices": ["approve", "deny"],
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
            self._states[state] = {"view": view, "request_id": item["request_id"], "decision": decision, "verifier": verifier,
                                   "challenge": challenge["challenge"], "expires": self.clock() + VIEW_LIFETIME}
        return {"url": self.authorize["endpoint"],
                "params": {"response_type": "code", "client_id": self.authorize["client_id"],
                           "redirect_uri": self.authorize["redirect_uri"], "scope": "openid", "state": state,
                           "nonce": challenge["nonce"], "code_challenge": pkce_challenge(verifier),
                           "code_challenge_method": "S256", "prompt": "login", "max_age": "0"}}

    # -- 3. Auth0 sends the owner back: record the decision, then act on it exactly once ---------------
    def finish(self, state, code, view=None):
        """``view``: the browser session cookie from the page, when the web layer has one; it must match."""
        with self._lock:
            self._sweep()
            item = self._states.pop(state if type(state) is str else "", None)      # single use
        if item is None or (view is not None and not hmac.compare_digest(str(view), item["view"])):
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
        try:
            moved = self.store.transition(rid, "pending", target)
        except Exception:
            raise ApprovalError("could_not_record_decision") from None          # nothing was decided or run
        if not moved:
            raise ApprovalError("request_not_pending")
        if decision == "deny":
            try:
                result = self.broker.deny(payload, id_token, item["challenge"])
            except Exception as error:
                # The owner said no. Even if recording the denial at the installer failed, nothing runs.
                return {"state": "denied", "request_id": rid, "recorded_by_installer": False,
                        "note": getattr(error, "code", "unavailable")}
            return {"state": "denied", "request_id": rid, "recorded_by_installer": bool(result.get("ok"))}
        method = self.broker.rollback if payload.get("kind") == "rollback" else self.broker.install
        try:
            self.store.transition(rid, "approved", "running")
            if self._pool is not None:
                self._pool.submit(self._execute, rid, method, payload, id_token, item["challenge"])
                return {"state": "running", "request_id": rid, "ok": None}
        except Exception:
            return self._uncertain(rid)
        return self._execute(rid, method, payload, id_token, item["challenge"])

    def _execute(self, rid, method, payload, id_token, challenge):
        """Run the approved action and settle the request's durable state. Never raises."""
        try:
            try:
                result = method(payload, id_token, challenge)
            except Exception as error:
                result = self._after_error(rid, error)
            state_ = self._state_for(result)
            self.store.transition(rid, "running", state_, result=result)
            return {"state": state_, "request_id": rid, "ok": bool(result.get("ok"))}
        except Exception:
            return self._uncertain(rid)

    def _uncertain(self, rid):
        """Something unexpected broke AFTER the owner approved: we can't say what happened, so say exactly that."""
        result = {"ok": False, "stopped": "unexpected_error_owner_must_verify", "changed_anything": None,
                  "needs_owner_intervention": True}
        for from_state in ("running", "approved"):
            try:
                if self.store.transition(rid, from_state, "needs_owner_intervention", result=result):
                    break
            except Exception:
                continue
        return {"state": "needs_owner_intervention", "request_id": rid, "ok": False}

    def status(self, request_id):
        """Safe, durable status of one request (what the approval page shows while an install runs)."""
        payload = self.store.payload(request_id)
        if payload is None:
            raise ApprovalError("unknown_request")
        return self.store.status(request_id, owner=payload.get("owner"), device=payload.get("device"))

    @staticmethod
    def _state_for(result):
        if result.get("needs_owner_intervention"):
            return "needs_owner_intervention"
        return "done" if result.get("ok") else "failed"

    def _after_error(self, rid, error):
        """The installer call raised. A refusal code alone proves nothing (the installer may have installed
        packages and then failed to save its result), so ask the installer's own durable record:
        no run recorded -> verified nothing ran; a finished record -> its real result; anything else
        (still 'running', unreachable, unknown) -> the owner must verify."""
        code = getattr(error, "code", None)
        result = self._root_result(rid)
        if result.get("stopped") == "installer_never_received_it":
            stopped = code if code and code != "installer_unavailable" else "installer_never_received_it"
            return {"ok": False, "stopped": stopped, "changed_anything": False}
        return result

    def _root_result(self, rid):
        """The installer's durable record for this request, as a result; unknown means the owner must verify."""
        try:
            record = self.broker.status(rid)
        except Exception:
            return {"ok": False, "stopped": "installer_unreachable_owner_must_verify", "changed_anything": None,
                    "needs_owner_intervention": True}
        state = record.get("state")
        result = record.get("result") or {}
        if state in ("done", "failed", "needs_owner_intervention") and isinstance(result, dict) and "ok" in result:
            return dict(result)
        if state == "denied":
            return {"ok": False, "stopped": "denied_by_owner", "changed_anything": False}
        if state == "not_started":
            return {"ok": False, "stopped": "installer_never_received_it", "changed_anything": False}
        return {"ok": False, "stopped": "installer_state_unknown_owner_must_verify", "changed_anything": None,
                "needs_owner_intervention": True}

    def recover(self):
        """Call once at startup. Every request left approved/running is reconciled with the installer's own
        record (never retried): finished runs get their real result, unknown ones are marked for the owner."""
        settled = []
        for rid in self.store.in_flight():
            result = self._root_result(rid)
            if self.store.transition(rid, "approved", "running") is False:
                pass                                           # was already running
            self.store.transition(rid, "running", self._state_for(result), result=result)
            settled.append(rid)
        return settled
