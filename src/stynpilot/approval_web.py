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
import secrets
import urllib.error
import urllib.parse
import urllib.request

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from .approval import ApprovalError, ApprovalFlow

COOKIE = "sp_approval"
_RID = re.compile(r"[a-f0-9]{64}\Z")
MAX_FORM = 4096
_STYLE = ("body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}"
          "li{margin:.4rem 0}button{font-size:1.1rem;padding:.7rem 1.4rem;margin:.5rem .5rem .5rem 0}"
          ".deny{background:#eee}.primary{background:#0a5;color:#fff;border:0;border-radius:.4rem;font-size:1.3rem;padding:1rem 1.6rem}code{background:#f3f3f3;padding:0 .3rem}")


_PASSKEY_JS = r"""
const box=document.getElementById('pk');const o=JSON.parse(box.dataset.o);const msg=document.getElementById('msg');
const u2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const r=atob(s);const b=new Uint8Array(r.length);for(let i=0;i<r.length;i++)b[i]=r.charCodeAt(i);return b};
const b2u=a=>{a=new Uint8Array(a);let t='';for(const x of a)t+=String.fromCharCode(x);return btoa(t).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const buttons=[...document.querySelectorAll('button[data-d]')];
function note(t){msg.textContent=t}
async function go(d){
  if(!window.PublicKeyCredential){note('This browser cannot use passkeys. Use the Auth0 sign-in below.');return}
  buttons.forEach(b=>b.disabled=true);note('Waiting for your phone to confirm it is you...');
  let sent=false;
  try{
    const c=await navigator.credentials.get({publicKey:{challenge:u2b(o.challenge[d]),rpId:o.rp_id,timeout:120000,userVerification:'required',
      allowCredentials:o.credentials.map(id=>({type:'public-key',id:u2b(id)}))}});
    const r=c.response;
    const a={credential_id:b2u(c.rawId),client_data_json:b2u(r.clientDataJSON),authenticator_data:b2u(r.authenticatorData),signature:b2u(r.signature)};
    note('Checking...');sent=true;
    const reply=await fetch('/approve/passkey',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({view:o.view,csrf:o.csrf,decision:d,assertion:JSON.stringify(a)})});
    const j=await reply.json();
    if(j.ok){location.href=j.next;return}
    note(j.message||'Refused.');if(j.next){location.href=j.next;return}
  }catch(e){
    if(sent){note('The answer did not arrive, so the result is uncertain. Opening the request status - check it before trying again.');
      setTimeout(()=>{location.href=o.status_url},2500);return}
    note('Cancelled or not completed. Nothing was changed. You can try again.')}
  buttons.forEach(b=>b.disabled=false);
}
buttons.forEach(b=>b.addEventListener('click',()=>go(b.dataset.d)));
"""

_ENROLL_JS = r"""
const box=document.getElementById('pk');const o=JSON.parse(box.dataset.o);const msg=document.getElementById('msg');
const u2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const r=atob(s);const b=new Uint8Array(r.length);for(let i=0;i<r.length;i++)b[i]=r.charCodeAt(i);return b};
const b2u=a=>{a=new Uint8Array(a);let t='';for(const x of a)t+=String.fromCharCode(x);return btoa(t).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const btn=document.getElementById('make');
btn.addEventListener('click',async()=>{
  if(!window.PublicKeyCredential){msg.textContent='This browser cannot create passkeys.';return}
  btn.disabled=true;msg.textContent='Waiting for your phone to confirm it is you...';
  let sent=false;
  try{
    const c=await navigator.credentials.create({publicKey:{challenge:u2b(o.challenge),rp:{id:o.rp_id,name:'StyNpilot'},
      user:{id:u2b(o.user_id),name:'owner',displayName:'StyNpilot owner'},pubKeyCredParams:[{type:'public-key',alg:-7}],
      authenticatorSelection:{residentKey:'preferred',userVerification:'required'},attestation:'none',timeout:120000,
      excludeCredentials:o.exclude.map(id=>({type:'public-key',id:u2b(id)}))}});
    const r=c.response;sent=true;
    const reply=await fetch('/approve/enroll/finish',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({view:o.view,csrf:o.csrf,response:{client_data_json:b2u(r.clientDataJSON),attestation_object:b2u(r.attestationObject)}})});
    const j=await reply.json();
    msg.textContent=j.message||'Done.';
    if(j.ok&&j.next){setTimeout(()=>{location.href=j.next},2500);return}
    if(j.ok){return}
  }catch(e){
    if(sent){msg.textContent='The answer did not arrive, so the result is uncertain. Ask the assistant to run passkey_status and check before trying again.';return}
    msg.textContent='Cancelled or not completed. You can try again until the time runs out.'}
  btn.disabled=false;
});
"""


def _page(title, body, status=200, extra_origin="", nonce=None):
    text = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><style>%s</style>%s" % (html.escape(title), _STYLE, body))
    response = HTMLResponse(text, status_code=status)
    response.headers["Cache-Control"] = "no-store"
    script = "script-src 'nonce-%s'; connect-src 'self'; " % nonce if nonce else ""
    response.headers["Content-Security-Policy"] = ("default-src 'none'; style-src 'unsafe-inline'; %sbase-uri 'none'; "
                                                   "form-action 'self' %s; frame-ancestors 'none'" % (script, extra_origin))
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
    "too_many_tries_open_the_request_again": "Too many tries on this page. Open the request again.",
}
_PASSKEY_REFUSALS = {
    "passkey_user_verification_required": "Your phone did not confirm it was you (fingerprint or screen lock). Try again.",
    "passkey_unknown_or_revoked": "That passkey is not enrolled here, or was removed.",
    "passkey_wrong_origin": "That passkey was used on a different address. Use the approval address.",
    "passkey_signature_invalid": "The passkey's signature did not check out. Nothing was changed.",
    "passkey_wrong_challenge": "This approval is for a different request. Open the request again.",
    "already_used": "This approval was already used. Open the request again.",
    "challenge_expired": "This approval page expired. Open the request again.",
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
        intro = ("<h1>Approve or deny</h1><p>This text was written by the installer on your computer, not by an "
                 "assistant. Request fingerprint: <code>%s</code></p><ul>%s</ul>" % (html.escape(view["fingerprint"]), lines))
        auth0 = ("<form method=post action=/approve/choose>"
                 "<input type=hidden name=view value='%s'><input type=hidden name=csrf value='%s'>"
                 "<button name=decision value=approve>Approve</button>"
                 "<button class=deny name=decision value=deny>Deny</button></form>"
                 "<p>Either choice asks you to sign in again to confirm. Nothing happens until you do.</p>"
                 % (html.escape(view["view"]), html.escape(view["csrf"])))
        nonce = None
        passkey = view.get("passkey")
        if passkey:
            nonce = secrets.token_urlsafe(18)
            options = dict(passkey, view=view["view"], csrf=view["csrf"], status_url=view["status_url"])
            warning = ("<p><b>Note:</b> at least one enrolled passkey is synced through your Google account, so anyone who can "
                       "sign in to that account could use it. Add a device-only passkey when you can.</p>"
                       if passkey["synced"] else "")
            body = (intro + "<div id=pk data-o='%s'></div>"
                    "<button class=primary data-d=approve>Approve with fingerprint or PIN</button>"
                    "<button class=deny data-d=deny>Deny</button><p id=msg role=status></p>"
                    "<p><small>Your phone decides how it confirms it is you (fingerprint, face or screen lock) and may accept a "
                    "recent unlock. StyNpilot requires that the phone reports it did.</small></p>%s"
                    "<details><summary>Use the Auth0 sign-in instead</summary>%s</details>"
                    "<script nonce='%s'>%s</script>"
                    % (html.escape(json.dumps(options, sort_keys=True), quote=True), warning, auth0, nonce, _PASSKEY_JS))
        else:
            body = intro + auth0
        response = _page("Approve or deny", body, 200, authorize_origin, nonce=nonce)
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

    def json_ok(origin):
        return origin == allowed_origin

    async def read_json(request):
        if not json_ok(request.headers.get("origin")) or "application/json" not in request.headers.get("content-type", ""):
            return None
        raw = await request.body()
        if len(raw) > 16384:
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            return None
        return data if isinstance(data, dict) else None

    def refused(error):
        code = error.code
        if code in _PASSKEY_REFUSALS:
            text = _PASSKEY_REFUSALS[code]
        elif code.startswith("passkey_refused_"):
            text = _PASSKEY_REFUSALS.get(code[len("passkey_refused_"):], "The passkey was not accepted (%s). Nothing was changed." % code[16:60])
        elif code in _MESSAGES:
            text = _MESSAGES[code]
        else:
            text = "Not completed (%s). Nothing was changed unless the status page says so." % code[:60]
        return JSONResponse({"ok": False, "message": text}, status_code=400, headers={"Cache-Control": "no-store"})

    async def passkey(request):
        data = await read_json(request)
        view = None if data is None else data.get("view")
        if data is None or request.cookies.get(COOKIE) != view or not view:
            return JSONResponse({"ok": False, "message": _MESSAGES["page_expired"]}, status_code=403)
        try:
            outcome = await run_in_threadpool(flow.passkey_decide, view, data.get("csrf"), data.get("decision"),
                                              data.get("assertion"))
        except ApprovalError as error:
            return refused(error)
        except Exception:
            try:
                where = "/approve/status/" + flow.request_of(view)
            except Exception:
                where = None
            return JSONResponse({"ok": False, "uncertain": True, "next": where,
                                 "message": "The outcome is uncertain. Check the request's status before trying again."},
                                status_code=500)
        response = JSONResponse({"ok": True, "state": outcome["state"], "next": "/approve/status/" + outcome["request_id"]},
                                headers={"Cache-Control": "no-store"})
        try:
            keep = flow.status(outcome["request_id"]).get("kind") == "passkey"       # the enrollment page needs this browser session
        except Exception:
            keep = False
        if not keep:
            response.delete_cookie(COOKIE, path="/approve")
        return response

    async def enroll(request):
        rid = request.path_params["rid"]
        if not _RID.fullmatch(rid):
            return _page("Not found", "<p>Not found.</p>", 404)
        info = await run_in_threadpool(flow.enroll_page, rid, request.cookies.get(COOKIE, ""))
        nonce = secrets.token_urlsafe(18)
        options = dict(info)
        body = ("<h1>Create your passkey</h1><p>Name: <b>%s</b>. Tap the button, then use your fingerprint or screen lock. "
                "This must be done within a few minutes.</p><div id=pk data-o='%s'></div>"
                "<button class=primary id=make>Create passkey</button><p id=msg role=status></p>"
                "<script nonce='%s'>%s</script>"
                % (html.escape(info["label"]), html.escape(json.dumps(options, sort_keys=True), quote=True), nonce, _ENROLL_JS))
        response = _page("Create passkey", body, 200, authorize_origin, nonce=nonce)
        response.set_cookie(COOKIE, info["view"], max_age=info["expires_in"], httponly=True, secure=secure_cookie,
                            samesite="lax", path="/approve")
        return response

    async def enroll_finish(request):
        data = await read_json(request)
        view = None if data is None else data.get("view")
        if data is None or request.cookies.get(COOKIE) != view or not view:
            return JSONResponse({"ok": False, "message": _MESSAGES["page_expired"]}, status_code=403)
        try:
            done = await run_in_threadpool(flow.enroll_finish, view, data.get("csrf"), data.get("response"))
        except ApprovalError as error:
            return refused(error)
        except Exception:
            return JSONResponse({"ok": False, "uncertain": True, "message": "The outcome is uncertain. Ask the assistant to run "
                                 "passkey_status and check before trying again."}, status_code=500)
        kind = "synced through your Google account" if done["synced"] else "stays on this device"
        if done.get("activation_request_id"):
            text = ("Passkey created: %s (%s). It cannot approve anything yet. Next: confirm it with your Auth0 sign-in (opening that now)."
                    % (done["label"], kind))
            body = {"ok": True, "message": text, "next": "/approve/" + done["activation_request_id"]}
        else:
            text = ("Passkey created: %s (%s), short ID %s. It cannot approve anything yet. To finish, at your computer run: "
                    "sudo stynpilot service passkeys --config /etc/stynpilot/installer.json --action activate --kid %s"
                    % (done["label"], kind, done["kid"], done["kid"]))
            body = {"ok": True, "message": text}
        response = JSONResponse(body, headers={"Cache-Control": "no-store"})
        response.delete_cookie(COOKIE, path="/approve")
        return response

    async def callback(request):
        if request.query_params.get("error"):
            return _page("Cancelled", "<h1>Cancelled</h1><p>The sign-in was cancelled. Nothing was changed; "
                                      "the request is still waiting.</p>")
        state, code = request.query_params.get("state"), request.query_params.get("code")
        if not state or not code:
            raise ApprovalError("unknown_or_used_state")
        outcome = await run_in_threadpool(flow.finish, state, code, request.cookies.get(COOKIE, ""))
        if outcome["state"] in ("running", "done") and (flow.status(outcome["request_id"]).get("kind") == "passkey"):
            return RedirectResponse("/approve/status/" + outcome["request_id"], status_code=303)      # cookie kept for enrollment
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
        if record.get("kind") == "passkey" and state == "done" and result.get("enrollment_open"):
            extra += "<p><a href='/approve/enroll/%s'>Create the passkey now</a> (fingerprint or screen lock).</p>" % html.escape(rid)
        if result.get("kid"):
            extra += "<p>Passkey short ID: <code>%s</code></p>" % html.escape(str(result["kid"]))
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
                             Route("/approve/passkey", wrap(passkey, may_have_acted=True), methods=["POST"]),
                             Route("/approve/enroll/finish", wrap(enroll_finish), methods=["POST"]),
                             Route("/approve/enroll/{rid}", wrap(enroll), methods=["GET"]),
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
