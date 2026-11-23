#!/usr/bin/python3 -I
"""Guest-side helpers for the VM test (run over ssh as the right user).  Prints one JSON object per call."""
import http.cookies
import json
import os
import ssl
import sys
import time
import urllib.parse

sys.path[:0] = ["/usr/lib/stynpilot/lib", "/usr/lib/stynpilot/vendor", "/mnt/payload/tests"]
import httpx

ISS = "https://auth.g8test.example/"
OWNER_SUB = "auth0|g8-owner"
DEVICE = "dtdev_G8TESTdevice00"
APPROVAL_HOST, MCP_HOST = "g8vm.example:8444", "g8vm.example"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
               "MCP-Protocol-Version": "2025-06-18"}
CTX = ssl.create_default_context()                              # the system store: the test CA is installed there


def out(**kw):
    print(json.dumps(kw, sort_keys=True))


def pairing():
    import time as _t
    from legacy_pairing import make_pairing_db
    from pathlib import Path
    try:
        from stynpilot.identity import account_id
        owner = account_id(verified_issuer=ISS, verified_subject=OWNER_SUB)
    except ImportError:                                  # Preview26 rehearsal: the new package is not installed yet
        owner = "acct_" + "e" * 40
    folder = Path.home() / ".local/state/stynpilot-owner"
    path = make_pairing_db(folder, [(DEVICE, owner, _t.time() + 86400, None,
                                     ["development.file.read", "workspace.propose", "workspace.review"])])
    out(ok=True, pairing=str(path), owner=owner)


def wizard(url):
    parts = urllib.parse.urlsplit(url)
    base = "http://%s" % parts.netloc
    c = httpx.Client(base_url=base, timeout=300, follow_redirects=False, trust_env=False)
    first = c.get(parts.path)
    assert first.status_code == 303, first.status_code
    again = c.get(parts.path)                                   # one-time link: must now be refused
    assert again.status_code == 410, "setup link was reusable"
    page = c.get("/setup")
    assert page.status_code == 200 and "pairing" in page.text.lower()
    found = ""
    for part in page.text.split("value='"):
        if part.startswith("/") and "pairing" in part:
            found = part.split("'")[0]
    form = {"issuer": "auth.g8test.example", "approval_client_id": "g8-approval-app",
            "approval_public_host": APPROVAL_HOST, "mcp_public_host": MCP_HOST, "pairing_db": found,
            "chatgpt_client_id": "chatgpt-connector", "claude_client_id": "claude-connector"}
    h = {"Origin": base}
    saved = c.post("/setup/save", data=form, headers=h)
    assert saved.status_code == 200 and "One step left" in saved.text, saved.text[:400]
    out(step="saved", pairing_found=found)
    sys.stdout.flush()
    if "--save-only" in sys.argv:                               # the owner fills the form; the password step comes later
        return
    done = c.post("/setup/system", data={"go": "1"}, headers=h)      # blocks while the password prompt is answered
    finished = "Setup is finished" in done.text
    out(step="system", finished=finished, page=done.text[-500:] if not finished else "")
    if finished:
        started = c.post("/setup/start", data={}, headers=h) if "--start" in sys.argv else None
        if started is not None:
            out(step="start", status=started.status_code, page=started.text[-300:])


def ai_token(azp):
    r = httpx.get(ISS + "ai-token", params={"azp": azp, "mcp_host": MCP_HOST}, verify=CTX, timeout=20, trust_env=False)
    return "Bearer " + r.json()["token"]


def mcp(azp, name, arguments, token=None):
    client = httpx.Client(base_url="http://127.0.0.1:18443", headers={"Host": MCP_HOST}, timeout=60, trust_env=False)
    reply = client.post("/mcp", headers={**MCP_HEADERS, "Authorization": token or ai_token(azp)},
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
    body = reply.json()
    if "result" not in body:
        return {"http": reply.status_code, "error": body}
    result = body["result"]
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


def approve(rid, decision="approve"):
    """The owner's browser: open the page, press the button, 'sign in' at the provider, come back."""
    c = httpx.Client(base_url="http://127.0.0.1:18444", headers={"Host": APPROVAL_HOST}, timeout=600, trust_env=False,
                     follow_redirects=False)
    page = c.get("/approve/" + rid)
    assert page.status_code == 200, (page.status_code, page.text[:300])
    view = page.text.split("name=view value='")[1].split("'")[0]
    csrf = page.text.split("name=csrf value='")[1].split("'")[0]
    cookie = {"Cookie": "sp_approval=" + view}
    summary = page.text.split("<ul>")[1].split("</ul>")[0]
    chosen = c.post("/approve/choose", data={"view": view, "csrf": csrf, "decision": decision},
                    headers={"Origin": "https://" + APPROVAL_HOST, **cookie})
    assert chosen.status_code == 303, (chosen.status_code, chosen.text[:300])
    idp = httpx.get(chosen.headers["location"], verify=CTX, follow_redirects=False, timeout=30, trust_env=False)
    assert idp.status_code == 302, (idp.status_code, idp.text[:200])
    back = urllib.parse.urlsplit(idp.headers["location"])
    done = c.get(back.path + "?" + back.query, headers=cookie)
    out(step="approval", http=done.status_code, location=done.headers.get("location"), summary=summary[:600],
        text=done.text[-300:] if done.status_code != 303 else "")


def wait_state(azp, rid, want, seconds):
    end = time.time() + seconds
    state = None
    while time.time() < end:
        state = mcp(azp, "commander_software_install_status", {"device_id": DEVICE, "request_id": rid})
        if state.get("result", {}).get("state") in want:
            break
        time.sleep(2)
    out(step="status", state=state)


def main():
    cmd = sys.argv[1]
    if cmd == "pairing":
        pairing()
    elif cmd == "wizard":
        wizard(sys.argv[2])
    elif cmd == "request":
        out(step="request", result=mcp(sys.argv[2], "commander_request_software_install",
                                       {"device_id": DEVICE, "software": sys.argv[3]}))
    elif cmd == "request-rollback":
        out(step="request-rollback", result=mcp(sys.argv[2], "commander_request_software_rollback",
                                                {"device_id": DEVICE, "software": sys.argv[3], "rollback_id": sys.argv[4]}))
    elif cmd == "status":
        wait_state(sys.argv[2], sys.argv[3], sys.argv[4].split(","), int(sys.argv[5]))
    elif cmd == "approve":
        approve(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "approve")
    elif cmd == "ai-cannot-approve":
        token = ai_token(sys.argv[2])
        client = httpx.Client(base_url="http://127.0.0.1:18443", headers={"Host": MCP_HOST}, timeout=20, trust_env=False)
        codes = {p: client.get(p).status_code for p in ("/approve/" + sys.argv[3], "/approve/choose", "/approve/callback")}
        listed = client.post("/mcp", headers={**MCP_HEADERS, "Authorization": token},
                             json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).json()["result"]["tools"]
        out(step="ai-cannot-approve", routes=codes, tools=[t["name"] for t in listed])
    elif cmd == "bad-token":
        out(step="bad-token", result=mcp("claude-connector", "commander_software_install_status",
                                         {"device_id": DEVICE, "request_id": "0" * 64}, token="Bearer not.a.token"))


main()
