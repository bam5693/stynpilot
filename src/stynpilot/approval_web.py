"""The owner's approval web page (owner-side process; NOT part of the AI-facing MCP service).

Routes (all under /approve):
  GET  /approve/<request id>   shows the root-written summary with explicit Approve and Deny buttons
  POST /approve/choose         CSRF + session checked; redirects to the Auth0 sign-in for that choice
  GET  /approve/callback       Auth0 returns here; the decision is recorded and acted on once

Session handling: a random per-page value kept in an HttpOnly, SameSite=Lax cookie scoped to /approve
(Secure when served over HTTPS). The page form, the CSRF token, the Auth0 ``state`` and the cookie must
all agree, so a link opened in another browser, a forged form post or a replayed callback is refused.
The Host header must be the configured public host and a POST's Origin must match it.

This module is deliberately not imported by anything under ``stynpilot.server`` (a test enforces it):
the AI-facing service can neither render nor alter this page, and holds no installer connection.
"""
from __future__ import annotations

import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from .approval import ApprovalError, ApprovalFlow

COOKIE = "sp_approval"
_RID = re.compile(r"[a-f0-9]{64}\Z")
MAX_FORM = 4096
_STYLE = ("body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}"
          "li{margin:.4rem 0}button{font-size:1.1rem;padding:.7rem 1.4rem;margin:.5rem .5rem .5rem 0}"
          ".deny{background:#eee}code{background:#f3f3f3;padding:0 .3rem}")


def _page(title, body, status=200, extra_origin=""):
    text = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><style>%s</style>%s" % (html.escape(title), _STYLE, body))
    response = HTMLResponse(text, status_code=status)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = ("default-src 'none'; style-src 'unsafe-inline'; "
                                                   "form-action 'self' %s; frame-ancestors 'none'" % extra_origin)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


_MESSAGES = {
    "unknown_request": "This request does not exist.",
    "request_not_pending": "This request has already been decided or has expired. Nothing was changed.",
    "page_expired": "This page expired. Open the request again.",
    "csrf_check_failed": "The form check failed. Open the request again.",
    "already_chosen": "A choice was already made on this page.",
    "unknown_or_used_state": "This sign-in link was already used or is not valid here. Nothing was changed.",
    "sign_in_failed": "The sign-in could not be completed. Nothing was changed; the request is still waiting.",
    "summary_altered_in_transit": "The summary did not match what the installer produced, so it is not shown.",
}


def _message(error):
    """Only codes raised before anything could change say "nothing was changed"; others say to check the status."""
    code = error.code
    if code in _MESSAGES:
        return _MESSAGES[code], True
    return "The request could not be completed (%s). Check its status before trying again." % html.escape(code[:60]), False


def build_app(*, flow: ApprovalFlow, public_host, secure_cookie=True):
    if type(public_host) is not str or not public_host or "/" in public_host:
        raise ValueError("public_host must be a bare host[:port]")
    allowed_origin = ("https://" if secure_cookie else "http://") + public_host
    authorize_origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(flow.authorize["endpoint"]))

    def host_ok(request):
        return request.headers.get("host", "").lower() == public_host.lower()

    def wrap(handler, may_have_acted=False):
        async def inner(request: Request):
            if not host_ok(request):
                return _page("Not found", "<p>Not found.</p>", 421)
            try:
                return await handler(request)
            except ApprovalError as error:
                text, unchanged = _message(error)
                return _page("Approval", "<h1>%s</h1><p>%s</p>" % ("Nothing was changed" if unchanged else "Check the status", text),
                             400, authorize_origin)
            except Exception:
                if may_have_acted:       # e.g. the callback: we cannot know how far it got
                    return _page("Check the status", "<h1>Check the status</h1><p>An unexpected error happened while "
                                 "completing this. The outcome is uncertain. Open the request's status page before "
                                 "trying again.</p>", 500)
                return _page("Error", "<h1>Something went wrong</h1><p>Open the request again.</p>", 500)
        return inner

    async def show(request):
        rid = request.path_params["rid"]
        if not _RID.fullmatch(rid):
            return _page("Not found", "<p>Not found.</p>", 404)
        view = await run_in_threadpool(flow.page, rid)
        lines = "".join("<li>%s</li>" % html.escape(line) for line in view["summary"])
        body = ("<h1>Approve or deny</h1><p>This text was written by the installer on your computer, not by an "
                "assistant. Request fingerprint: <code>%s</code></p><ul>%s</ul>"
                "<form method=post action=/approve/choose>"
                "<input type=hidden name=view value='%s'><input type=hidden name=csrf value='%s'>"
                "<button name=decision value=approve>Approve</button>"
                "<button class=deny name=decision value=deny>Deny</button></form>"
                "<p>Either choice asks you to sign in again to confirm. Nothing happens until you do.</p>"
                % (html.escape(view["fingerprint"]), lines, html.escape(view["view"]), html.escape(view["csrf"])))
        response = _page("Approve or deny", body, 200, authorize_origin)
        response.set_cookie(COOKIE, view["view"], max_age=view["expires_in"], httponly=True, secure=secure_cookie,
                            samesite="lax", path="/approve")
        return response

    async def choose(request):
        origin = request.headers.get("origin")
        if origin is not None and origin != allowed_origin:
            return _page("Refused", "<p>Refused.</p>", 403)
        raw = await request.body()
        if len(raw) > MAX_FORM:
            return _page("Refused", "<p>Refused.</p>", 413)
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace"), max_num_fields=8).items()}
        view = form.get("view", "")
        if request.cookies.get(COOKIE) != view or not view:
            return _page("Refused", "<h1>Nothing was changed</h1><p>%s</p>" % _MESSAGES["page_expired"], 403)
        started = await run_in_threadpool(flow.choose, view, form.get("csrf"), form.get("decision"))
        return RedirectResponse(started["url"] + "?" + urllib.parse.urlencode(started["params"]), status_code=303)

    async def callback(request):
        if request.query_params.get("error"):
            return _page("Cancelled", "<h1>Cancelled</h1><p>The sign-in was cancelled. Nothing was changed; "
                                      "the request is still waiting.</p>")
        state, code = request.query_params.get("state"), request.query_params.get("code")
        if not state or not code:
            raise ApprovalError("unknown_or_used_state")
        outcome = await run_in_threadpool(flow.finish, state, code, request.cookies.get(COOKIE, ""))
        if outcome["state"] == "running":              # long install: answer now, show progress on the status page
            redirect = RedirectResponse("/approve/status/" + outcome["request_id"], status_code=303)
            redirect.delete_cookie(COOKIE, path="/approve")
            return redirect
        text = {"done": "Approved. The installer ran the plan and finished.",
                "failed": "Approved, but the installer stopped or refused. See the request status for why.",
                "denied": "Denied. Nothing was changed.",
                "needs_owner_intervention": "Approved, but something needs your attention: the installer could not "
                                            "confirm the machine is back in its original state. Check before "
                                            "installing anything else."}[outcome["state"]]
        response = _page("Done", "<h1>%s</h1>" % html.escape(text))
        response.delete_cookie(COOKIE, path="/approve")
        return response

    _STATUS_TEXT = {
        "pending": "Waiting for the owner's decision.",
        "approved": "Approved; starting.",
        "running": "Running. This can take a while; this page refreshes by itself.",
        "done": "Finished.",
        "failed": "The installer stopped or refused. Nothing it stopped on was left half-done unless noted below.",
        "denied": "Denied. Nothing was changed.",
        "expired": "Expired before it was decided. Nothing was changed.",
        "needs_owner_intervention": "Needs your attention: the installer could not confirm the machine is back in "
                                    "its original state, or its outcome is uncertain. Check before installing anything else.",
    }

    async def status(request):
        rid = request.path_params["rid"]
        if not _RID.fullmatch(rid):
            return _page("Not found", "<p>Not found.</p>", 404)
        record = await run_in_threadpool(flow.status, rid)
        state = record["state"]
        extra = ""
        result = record.get("result") or {}
        if result.get("stopped"):
            extra += "<p>Reason: <code>%s</code></p>" % html.escape(str(result["stopped"])[:80])
        if result.get("limits"):
            extra += "<p>%s</p>" % html.escape(str(result["limits"]))
        if result.get("to_version"):
            extra += "<p>StyNpilot %s &rarr; %s</p>" % (html.escape(str(result.get("from_version", ""))[:40]),
                                                     html.escape(str(result["to_version"])[:40]))
        if result.get("rolled_back"):
            extra += ("<p>The new version did not pass its checks, so StyNpilot put the previous version back "
                      "automatically.</p>")
        if state in ("approved", "running"):
            extra += ("<p>An upgrade restarts StyNpilot for about a minute. If this page stops loading, wait a "
                      "minute and reload it.</p>")
        refresh = "<meta http-equiv=refresh content=3>" if state in ("approved", "running") else ""
        return _page("Status", "%s<h1>%s</h1><p>%s</p>%s" % (refresh, html.escape(state.replace("_", " ").title()),
                                                          html.escape(_STATUS_TEXT.get(state, state)), extra))

    return Starlette(routes=[Route("/approve/choose", wrap(choose), methods=["POST"]),
                             Route("/approve/callback", wrap(callback, may_have_acted=True), methods=["GET"]),
                             Route("/approve/status/{rid}", wrap(status), methods=["GET"]),
                             Route("/approve/{rid}", wrap(show), methods=["GET"])])


def token_exchange(*, token_endpoint, client_id, redirect_uri, timeout=10, allow_loopback_http=False):
    """Auth0 code -> ID token (public client, PKCE). The installer verifies the token itself; this only fetches it."""
    parts = urllib.parse.urlsplit(token_endpoint)
    if not (parts.scheme == "https" or (allow_loopback_http and parts.scheme == "http" and parts.hostname == "127.0.0.1")):
        raise ValueError("HTTPS token endpoint required")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)

    def exchange(code, verifier):
        data = urllib.parse.urlencode({"grant_type": "authorization_code", "client_id": client_id, "code": code,
                                       "code_verifier": verifier, "redirect_uri": redirect_uri}).encode()
        request = urllib.request.Request(token_endpoint, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        with opener.open(request, timeout=timeout) as reply:
            body = json.loads(reply.read(65536).decode("utf-8"))
        token = body.get("id_token") if isinstance(body, dict) else None
        if type(token) is not str or not token:
            raise ValueError("no id_token")
        return token
    return exchange
