"""Drives the REAL setup page in real Chrome (Playwright): opens the one-time link, fills the form, presses Save.
Needs google-chrome + playwright (dev only; not part of the package). Exit 0 only if Save is accepted.
Usage: python3 tools/browser_setup_check.py [path-to-source-tree]"""
import os
import socket
import sys
import tempfile
import threading
import time

root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(root, "src"))
sys.path.insert(0, os.path.join(root, "tests"))
import uvicorn  # noqa: E402
from legacy_pairing import make_pairing_db  # noqa: E402
from pathlib import Path  # noqa: E402
from stynpilot import setup_wizard  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

home = Path(tempfile.mkdtemp()); os.environ["HOME"] = str(home)
make_pairing_db(home / ".local/state/stynpilot-owner", [("dtdev_TESTONLYliveDevice", "acct_" + "a" * 40, time.time() + 3600, None, ["workspace.propose"])])
setup_wizard.ROOT_UID = os.geteuid()
sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
app = setup_wizard.build_app(home=home, uid=os.geteuid(), token="tok-browser-check", port=port,
                             root_runner=lambda src: type("R", (), {"returncode": 126})(), root_config=home / "etc-installer.json")
server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
threading.Thread(target=server.run, daemon=True).start()
time.sleep(1.5)
values = {"issuer": "tenant.example.test", "approval_client_id": "approvalid1", "approval_public_host": "pc.example.test:8443",
          "mcp_public_host": "pc.example.test", "chatgpt_client_id": "chatgptid1", "claude_client_id": "claudeid1"}
with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page()
    seen = []
    page.on("request", lambda r: seen.append((r.method, r.url, r.headers.get("origin"))) if r.method == "POST" else None)
    page.goto("http://127.0.0.1:%d/setup/tok-browser-check" % port)
    print("pairing field prefilled with:", page.input_value("input[name=pairing_db]") or "(empty)")
    if not page.input_value("input[name=pairing_db]"):
        page.fill("input[name=pairing_db]", str(home / ".local/state/stynpilot-owner/pairing.sqlite3"))
    for name, value in values.items():
        page.fill("input[name=%s]" % name, value)
    page.click("button")
    page.wait_for_load_state()
    text = page.inner_text("body")
    browser.close()
print("POST Origin header the browser sent:", seen)
print("page after Save:", text[:160].replace("\n", " | "))
ok = "One step left" in text
sys.exit(0 if ok else 1)
