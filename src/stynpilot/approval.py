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


class _PreflightFailed(Exception):
    pass


class ApprovalError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


class ApprovalFlow:
    """``broker``: object with challenge(payload, decision), install/rollback/deny(payload, proof, challenge).
    ``exchange``: callable(code, code_verifier) -> Auth0 ID token string.
    ``authorize``: dict(endpoint, client_id, redirect_uri)."""

    def __init__(self, *, store, broker, exchange, authorize, clock=time.time, background=False, before_run=None):
        if (type(authorize) is not dict or type(authorize.get("endpoint")) is not str
                or not authorize["endpoint"].startswith("https://")
                or type(authorize.get("redirect_uri")) is not str
                or not authorize["redirect_uri"].startswith(("https://", "http://127.0.0.1"))
                or type(authorize.get("client_id")) is not str or not authorize["client_id"]):
            raise ValueError("authorize needs an https endpoint, a client_id and an https (or loopback) redirect_uri")
        self.store, self.broker, self.exchange, self.authorize = store, broker, exchange, dict(authorize)
        self.clock, self._lock = clock, threading.Lock()
        self.before_run = before_run          # optional owner-side step (e.g. an owner-state backup) before an upgrade runs
        # background=True: the install runs on ONE worker thread, so the approval page and its other requests
        # stay responsive during a long install. Progress is the request's durable state (running -> done...).
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="stynpilot-approve") if background else None
        self._views, self._states, self._enroll_sessions = {}, {}, {}

    def _sweep(self):
        now = self.clock()
        for table in (self._views, self._states, self._enroll_sessions):
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
        adds = payload.get("kind") == "passkey" and payload.get("action") in ("enroll", "activate")
        passkey = None if adds else self._passkey_options(approve, deny)      # adding a passkey is Auth0-only
        with self._lock:
            self._sweep()
            if len(self._views) >= MAX_VIEWS:
                raise ApprovalError("too_many_open_approval_pages")
            self._views[view] = {"request_id": request_id, "csrf": csrf, "challenges": {"approve": approve, "deny": deny},
                                 "used": False, "attempts": 0, "expires": self.clock() + VIEW_LIFETIME}
        return {"passkey": passkey, "status_url": "/approve/status/" + request_id, "view": view, "csrf": csrf, "request_id": request_id, "kind": payload.get("kind", "install"),
                "summary": list(approve["summary"]), "summary_sha256": approve["summary_sha256"],
                "fingerprint": request_id[:12], "choices": ["approve", "deny"],
                "expires_in": VIEW_LIFETIME}

    def _passkey_options(self, approve, deny):
        """What the page's one-tap button needs: enrolled passkeys and the two challenges (the decision nonces).
        Absent or unreachable passkeys simply mean the Auth0 buttons are shown instead."""
        lister = getattr(self.broker, "passkey_list", None)
        if lister is None:
            return None
        try:
            info = lister()
        except Exception:
            return None
        keys = info.get("passkeys") if isinstance(info, dict) else None
        if not info.get("configured") or not keys:
            return None
        return {"rp_id": info["rp_id"], "credentials": [k["credential_id"] for k in keys],
                "synced": any(k["synced"] for k in keys),
                "challenge": {"approve": b64u(bytes.fromhex(approve["nonce"])), "deny": b64u(bytes.fromhex(deny["nonce"]))}}

    # -- 1b. one tap: a passkey signs the exact decision nonce ------------------------------------------------------------
    MAX_PASSKEY_TRIES = 5

    def passkey_decide(self, view, csrf, decision, assertion):
        """``assertion``: JSON text of the WebAuthn proof. The installer checks it WITHOUT using anything up first, so a
        wrong finger, a cancelled prompt or a bad signature leaves the request exactly as it was (up to a few tries)."""
        if decision not in ("approve", "deny"):
            raise ApprovalError("invalid_decision")
        with self._lock:
            self._sweep()
            item = self._views.get(view if type(view) is str else "")
            if item is None or item.get("enroll"):
                raise ApprovalError("page_expired")
            if type(csrf) is not str or not hmac.compare_digest(csrf, item["csrf"]):
                raise ApprovalError("csrf_check_failed")
            if item["used"]:
                raise ApprovalError("already_chosen")
            if item["attempts"] >= self.MAX_PASSKEY_TRIES:
                raise ApprovalError("too_many_tries_open_the_request_again")
            item["attempts"] += 1
        payload = self.store.payload(item["request_id"])
        if payload is None:
            raise ApprovalError("unknown_request")
        challenge = item["challenges"][decision]["challenge"]
        try:
            self.broker.passkey_precheck(payload, assertion, challenge, decision)
        except Exception as error:
            raise ApprovalError("passkey_refused_%s" % getattr(error, "code", "unavailable")) from None
        with self._lock:
            if item["used"]:
                raise ApprovalError("already_chosen")
            item["used"] = True
        return self._conclude(item["request_id"], decision, payload, assertion, challenge, view=view)

    # -- 2. the owner picks Approve or Deny: start a fresh Auth0 sign-in for exactly that choice --------
    def choose(self, view, csrf, decision):
        if decision not in ("approve", "deny"):
            raise ApprovalError("invalid_decision")
        with self._lock:
            self._sweep()
            item = self._views.get(view if type(view) is str else "")
            if item is None or item.get("enroll"):
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
        return self._conclude(rid, decision, payload, id_token, item["challenge"], view=item["view"])

    def _conclude(self, rid, decision, payload, proof, challenge, view=None):
        """Record the owner's decision and act on it exactly once (Auth0 token or passkey assertion: same path)."""
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
                result = self.broker.deny(payload, proof, challenge)
            except Exception as error:
                # The owner said no. Even if recording the denial at the installer failed, nothing runs.
                return {"state": "denied", "request_id": rid, "recorded_by_installer": False,
                        "note": getattr(error, "code", "unavailable")}
            return {"state": "denied", "request_id": rid, "recorded_by_installer": bool(result.get("ok"))}
        if payload.get("kind") == "passkey" and payload.get("action") == "enroll" and view:
            with self._lock:                 # only the browser that approved may then create the passkey
                self._enroll_sessions[rid] = {"view": view, "expires": self.clock() + VIEW_LIFETIME}
        wanted = {"rollback": "rollback", "upgrade": "upgrade", "runner": "runner_admin",
                  "passkey": "passkey_admin"}.get(payload.get("kind"), "install")
        method = getattr(self.broker, wanted, None)
        if method is None:
            return self._uncertain(rid)
        try:
            self.store.transition(rid, "approved", "running")
            if self._pool is not None:
                self._pool.submit(self._execute, rid, method, payload, proof, challenge)
                return {"state": "running", "request_id": rid, "ok": None}
        except Exception:
            return self._uncertain(rid)
        return self._execute(rid, method, payload, proof, challenge)

    def request_of(self, view):
        with self._lock:
            item = self._views.get(view if type(view) is str else "")
        if item is None:
            raise ApprovalError("page_expired")
        return item["request_id"]

    # -- passkey enrollment: after an enrollment request is approved, the phone creates the key -------------------------------
    def enroll_page(self, request_id, session=""):
        """Only for an enrollment request the installer has opened a window for, and only in the browser that approved it
        (the challenge goes to that browser alone). The challenge itself comes from the installer."""
        with self._lock:
            self._sweep()
            owner_session = self._enroll_sessions.get(request_id)
        if owner_session is None or type(session) is not str or not hmac.compare_digest(session, owner_session["view"]):
            raise ApprovalError("enrollment_not_for_this_browser")
        try:
            info = self.broker.passkey_begin(request_id)
        except Exception as error:
            raise ApprovalError("enrollment_%s" % getattr(error, "code", "unavailable")) from None
        view, csrf = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        with self._lock:
            self._sweep()
            if len(self._views) >= MAX_VIEWS:
                raise ApprovalError("too_many_open_approval_pages")
            self._views[view] = {"request_id": request_id, "csrf": csrf, "enroll": True, "used": False, "attempts": 0,
                                 "expires": self.clock() + min(VIEW_LIFETIME, info["expires_in"])}
            self._enroll_sessions[request_id] = {"view": view, "expires": self.clock() + VIEW_LIFETIME}
        return {"view": view, "csrf": csrf, "request_id": request_id, "label": info["label"], "rp_id": info["rp_id"],
                "challenge": b64u(bytes.fromhex(info["challenge"])), "exclude": list(info["exclude"]),
                "user_id": info["user_id"], "expires_in": info["expires_in"]}

    def enroll_finish(self, view, csrf, response):
        with self._lock:
            self._sweep()
            item = self._views.get(view if type(view) is str else "")
            if item is None or not item.get("enroll"):
                raise ApprovalError("page_expired")
            if type(csrf) is not str or not hmac.compare_digest(csrf, item["csrf"]):
                raise ApprovalError("csrf_check_failed")
            if item["used"] or item["attempts"] >= self.MAX_PASSKEY_TRIES:
                raise ApprovalError("already_chosen")
            item["attempts"] += 1
        try:
            done = self.broker.passkey_complete(item["request_id"], response)
        except Exception as error:
            raise ApprovalError("enrollment_%s" % getattr(error, "code", "unavailable")) from None
        with self._lock:
            item["used"] = True
        # The key now exists but is POWERLESS. Activation is a separate request that names this exact key; the owner approves it
        # with the Auth0 sign-in, whose nonce commits to the key's hash.
        try:
            remote = bool(self.broker.passkey_list().get("remote_activation"))
        except Exception:
            remote = False
        # By default the owner finishes at the computer's console (independent of this service); see passkey_console.py.
        done["activation_request_id"] = self._file_activation(item["request_id"], done) if remote else None
        return done

    def _file_activation(self, enroll_rid, done):
        from types import SimpleNamespace
        from datetime import datetime, timedelta, timezone
        from .broker.proof import render_summary
        original = self.store.payload(enroll_rid)
        if original is None:
            raise ApprovalError("unknown_request")
        expires = datetime.fromtimestamp(self.clock(), timezone.utc) + timedelta(minutes=15)
        payload = {"kind": "passkey", "action": "activate", "label": done["label"], "kid": done["kid"], "pub": done["pub"],
                   "owner": original["owner"], "device": original["device"], "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}
        try:
            receipt, _ = self.store.submit(kind="passkey", software="stynpilot-passkey-activate-" + done["kid"],
                                           device=original["device"], owner=original["owner"],
                                           proposer=SimpleNamespace(client="approval-page", name="approval page"),
                                           payload=payload, summary=render_summary(payload), expires=expires.timestamp())
        except RequestError:
            raise ApprovalError("could_not_file_the_activation_request") from None
        return receipt["request_id"]

    def _execute(self, rid, method, payload, id_token, challenge):
        """Run the approved action and settle the request's durable state. Never raises."""
        try:
            try:
                if self.before_run is not None:
                    try:
                        self.before_run(payload, rid)
                    except Exception:
                        raise _PreflightFailed() from None
                result = method(payload, id_token, challenge)
            except _PreflightFailed:
                result = {"ok": False, "stopped": "owner_state_backup_failed", "changed_anything": False}
            except Exception as error:
                result = self._after_error(rid, error, payload.get("kind"))
            if result.get("pending"):
                return {"state": "running", "request_id": rid, "ok": None}   # settled later from the installer's record
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

    def _after_error(self, rid, error, kind=None):
        """The installer call raised. A refusal code alone proves nothing (the installer may have installed
        packages and then failed to save its result), so ask the installer's own durable record:
        no run recorded -> verified nothing ran; a finished record -> its real result; anything else
        (still 'running', unreachable, unknown) -> the owner must verify."""
        code = getattr(error, "code", None)
        if kind == "upgrade":
            seen, record = self._root_record(rid)
            if seen == "record" and (record or {}).get("state") == "running":
                return {"ok": None, "pending": True}       # the upgrade worker is running; its result settles this
        result = self._root_result(rid)
        if result.get("stopped") == "installer_never_received_it":
            stopped = code if code and code != "installer_unavailable" else "installer_never_received_it"
            return {"ok": False, "stopped": stopped, "changed_anything": False}
        return result

    def _root_record(self, rid):
        """('unreachable', None) when the installer can't be asked right now; else ('record', status dict)."""
        try:
            return "record", self.broker.status(rid)
        except Exception as error:
            if isinstance(error, OSError) or getattr(error, "code", None) == "installer_unavailable":
                return "unreachable", None
            return "unknown", None

    def _root_result(self, rid):
        """The installer's durable record for this request, as a result; unknown means the owner must verify."""
        kind, record = self._root_record(rid)
        if kind != "record":
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

    def recover(self, patient=False):
        """Call at startup. Every request left approved/running is reconciled with the installer's own
        record (never retried): finished runs get their real result, unknown ones are marked for the owner.

        ``patient=True`` (the packaged service, where the root installer may simply start a moment later):
        if the installer can't be reached, or says the run is still going, the request is LEFT as it is and
        returned in the second list to be tried again; nothing is marked for the owner on a mere delay."""
        settled, waiting = [], []
        for rid in self.store.in_flight():
            if patient:
                kind, record = self._root_record(rid)
                if kind == "unreachable" or (kind == "record" and (record or {}).get("state") == "running"):
                    waiting.append(rid)
                    continue
            result = self._root_result(rid)
            if self.store.transition(rid, "approved", "running") is False:
                pass                                           # was already running
            self.store.transition(rid, "running", self._state_for(result), result=result)
            settled.append(rid)
        return (settled, waiting) if patient else settled

    def _settle_from_root(self, rid):
        result = self._root_result(rid)
        self.store.transition(rid, "approved", "running")
        self.store.transition(rid, "running", self._state_for(result), result=result)

    def give_up_waiting(self, rids):
        """The installer stayed unreachable (or 'running') for too long: say honestly that the owner must verify."""
        result = {"ok": False, "stopped": "installer_unreachable_owner_must_verify", "changed_anything": None,
                  "needs_owner_intervention": True}
        for rid in rids:
            self.store.transition(rid, "approved", "running")
            self.store.transition(rid, "running", "needs_owner_intervention", result=result)
