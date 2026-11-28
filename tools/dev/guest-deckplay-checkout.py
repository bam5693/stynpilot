"""Exercise the installed DeckPlay MCP and owner phone approval, without a NIC."""
import base64
import html
import json
from pathlib import Path
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))
fixture = __import__("guest-restore")

import httpx
import jwt
from softauth import SoftAuthenticator
from stynpilot import managed_activity, root_restore
from stynpilot.approval_web import COOKIE
from stynpilot.broker.helper import checkout_unit
from stynpilot.broker.passkeys import PasskeyStore

HOST = "owner.example.test"
SEED = r'''
import hashlib, json, subprocess, sys
from pathlib import Path
sys.path.insert(0, "/usr/lib/stynpilot/lib")
from stynpilot import repo_archive, repo_git
path = Path(sys.argv[1]); path.mkdir(mode=0o700)
def git(*argv):
    return subprocess.check_output(["/usr/bin/git", "-c", "user.name=Fixture", "-c",
                                    "user.email=a@example.invalid", "-C", str(path), *argv],
                                   env=repo_git._ENV).decode().strip()
git("init", "-q", "-b", "main")
(path / "README").write_text("old\n")
(path / ".env").write_text("synthetic historical credential\n")
git("add", "."); git("commit", "-qm", "old")
old = git("rev-parse", "HEAD")
git("rm", ".env")
(path / "README").write_text("reviewed tree\n")
git("commit", "-qam", "current")
new = git("rev-parse", "HEAD")
git("clone", "-q", "--bare", ".", "bare.git")
archive = path / "archive"
r = repo_archive.capture_prepared(path / "bare.git", archive, "github", repo_git.DECKPLAY_ORIGIN,
                                  {"refs/heads/main": new}, default_head="refs/heads/main")
print(json.dumps([old, new, str(archive), hashlib.sha256((archive/"manifest.json").read_bytes()).hexdigest(), r["bundle_sha256"]]))
'''


def main():
    key = fixture.setup(check_restore_path=False, lab=True)
    keys = PasskeyStore(fixture.STATE / "passkeys.sqlite3", rp_id=HOST, origin="https://" + HOST)
    authenticator = SoftAuthenticator("https://" + HOST, HOST)
    enrollment = "e" * 64
    keys.open_window(enrollment, "DeckPlay fixture owner", "fixture")
    enrolled = keys.complete(enrollment, authenticator.register(bytes.fromhex(keys.begin(enrollment)["challenge"])))
    keys.activate(enrolled["kid"], enrolled["label"], enrolled["pub"], enrollment, "fixture")
    old, new, path, manifest, bundle = json.loads(fixture.as_owner("/usr/bin/python3", "-IB", "-c", SEED,
                                                                   str(fixture.HOME / "deckplay-fixture")).stdout)
    adopted = fixture.as_owner("/usr/bin/stynpilot", "archive-adopt", "--config", str(fixture.CONFIG), "--archive", path,
                                "--manifest-sha256", manifest, "--bundle-sha256", bundle, "--client", "synthetic")
    archive_id = json.loads(adopted.stdout)["archive_id"]
    workspace = fixture.HOME / "StyNpilot-Projects/deckplay-hq"
    args = {"archive_id": archive_id, "ref": "refs/heads/main", "commit": new}

    with (httpx.Client(base_url="http://127.0.0.1:18443", headers={"Host": HOST}, timeout=110, trust_env=False) as mcp,
          httpx.Client(base_url="http://127.0.0.1:18444", headers={"Host": HOST}, timeout=30, trust_env=False) as phone):
        def call(tool, client="fixture", **arguments):
            now = int(time.time())
            token = jwt.encode({"iss": fixture.ISSUER, "aud": "https://" + HOST + "/mcp", "sub": "fixture|test-owner",
                                "iat": now, "exp": now + 300, "azp": client, "scope": "health.read workspace.propose"},
                               key, algorithm="RS256", headers={"kid": "fixture"})
            response = mcp.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": tool, "arguments": {"device_id": fixture.DEVICE, **arguments}}},
                headers={"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream",
                         "MCP-Protocol-Version": "2025-03-26"})
            response.raise_for_status()
            result = response.json()["result"]
            return result.get("structuredContent") or json.loads(result["content"][0]["text"])

        def ok(tool, **arguments):
            answer = call(tool, **arguments)
            assert answer["ok"], answer
            return answer["result"]

        def approve(rid, *, required=False):
            page = phone.get("/approve/" + rid)
            page.raise_for_status()
            if required:
                assert "Approval requires an enrolled passkey" in page.text
            options = json.loads(html.unescape(re.search("data-o='([^']+)'", page.text).group(1)))
            nonce = base64.urlsafe_b64decode(options["challenge"]["approve"] + "==")
            answer = phone.post("/approve/passkey", headers={"Origin": "https://" + HOST, "Cookie": COOKIE + "=" + options["view"]},
                                json={"view": options["view"], "csrf": options["csrf"], "decision": "approve",
                                      "assertion": json.dumps(authenticator.assert_(nonce))})
            answer.raise_for_status()
            assert answer.json()["ok"], answer.text
            return fixture.until(lambda: (result if (result := fixture.broker("status", rid))["state"] in
                                           ("done", "failed", "needs_owner_intervention") else None), 120)

        assert approve(ok("commander_request_workspace_authorization", name="deckplay-hq")["request_id"])["state"] == "done"
        test = ok("runner_selftest")
        assert len(test["passed"]) == 21 and not test["failed"] and not test["unverified"], test
        interrupt = "a" * 32
        scratch = workspace.parent / (".stynpilot-deckplay-checkout-" + interrupt)
        fixture.as_owner("mkdir", "-m", "700", str(scratch))
        fixture.as_owner("touch", str(scratch / "partial"))
        with root_restore.admission(fixture.STATE, exclusive=True):
            managed_activity.claim(fixture.STATE, "deckplay_checkout", interrupt)
            (fixture.STATE / ("deckplay-dispatch-" + interrupt)).write_text("synthetic interrupted staging")
            fixture.command("systemd-run", "--quiet", "--collect", "--service-type=exec", "--unit=" + checkout_unit(interrupt),
                            "--property=Slice=system.slice", "--property=KillMode=control-group", "/usr/bin/sleep", "120")
            try:
                managed_activity.require_idle(fixture.STATE)
            except managed_activity.ActivityError:
                pass
            else:
                raise AssertionError("Recovery admission ignored the checkout claim")
        fixture.command("systemctl", "restart", "stynpilot-installer.service")
        fixture.until(lambda: not (fixture.STATE / "managed-activity").exists(), 35)
        assert not scratch.exists() and not list(workspace.iterdir())
        plan = ok("deckplay_checkout_preview", **args)
        assert plan["plan"]["eligible"] and not list(workspace.iterdir())
        assert call("deckplay_checkout_preview", client="fixture-other", **args)["error"] == "archive_not_found"
        filed = ok("commander_request_deckplay_checkout", **args, plan_sha256=plan["plan_sha256"])
        # Approved plan is revalidated after the request was filed, so changes
        # in storage cannot be hidden behind a previously successful preview.
        retained = fixture.HOME / ".local/state/stynpilot/repository-archives" / archive_id / "archive/source.bundle"
        changed = retained.read_bytes()
        with retained.open("ab") as f:
            f.write(b"changed after review")
        result = approve(filed["request_id"], required=True)
        assert result["state"] == "failed" and "archive_bundle_digest_mismatch" in str(result), result
        assert not list(workspace.iterdir())
        retained.write_bytes(changed)
        time.sleep(1.1)
        filed = ok("commander_request_deckplay_checkout", **args, plan_sha256=plan["plan_sha256"])
        result = approve(filed["request_id"], required=True)
        assert result["state"] == "done", result
        assert not (fixture.STATE / "managed-activity").exists()
        assert (workspace / "README").read_text() == "reviewed tree\n" and not (workspace / ".env").exists()
        assert call("deckplay_checkout_preview", **args)["error"] == "checkout_workspace_not_empty"

        def git(*arguments):
            return fixture.as_owner("/usr/bin/git", "-C", str(workspace), *arguments).stdout.strip()

        assert git("rev-list", "--count", "HEAD") == "1"
        assert git("rev-parse", "HEAD") != new
        assert git("rev-parse", "HEAD^{tree}") == plan["plan"]["source_tree"]
        try:
            git("cat-file", "-t", old)
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError("Original history reached the working repository")
    print("STYNPILOT_PACKAGED_DECKPLAY_CHECKOUT_OK", flush=True)


if __name__ == "__main__":
    main()
