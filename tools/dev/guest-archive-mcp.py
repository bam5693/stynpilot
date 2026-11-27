"""Use the installed archive owner command and read-only MCP in a NIC-free guest."""
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))
fixture = __import__("guest-restore")

import httpx
import jwt
from stynpilot.upgrade_worker import endpoint_answers

HOST = "owner.example.test"
SEED = r'''
import hashlib, json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0, "/usr/lib/stynpilot/lib")
from stynpilot import repo_archive, repo_git
path = Path(sys.argv[1]); path.mkdir(mode=0o700)
def git(*argv):
    return subprocess.check_output(["/usr/bin/git", "-c", "user.name=Fixture", "-c",
                                    "user.email=a@example.invalid", "-C", str(path), *argv],
                                   env=repo_git._ENV).decode().strip()
git("init", "-q", "-b", "main")
(path / "README").write_text("first\n" + ("password=only-in-old-commit\n" if sys.argv[2] == "redact" else ""))
git("add", "README"); git("commit", "-qm", "first"); git("tag", "-am", "first", "v1")
old = git("rev-parse", "HEAD")
(path / "README").write_text("second\n"); git("commit", "-qam", "second")
new = git("rev-parse", "HEAD")
git("clone", "-q", "--bare", ".", "bare.git")
refs = dict(line.split() for line in git("-C", "bare.git", "for-each-ref", "--format=%(refname) %(objectname)").splitlines())
rows = []
for label in ("first", "second"):
    target = path / label
    receipt = repo_archive.capture_prepared(path / "bare.git", target, "github", "https://github.com/fixture/" + label + ".git",
                                            refs, default_head="refs/heads/main")
    rows.append([str(target), hashlib.sha256((target / "manifest.json").read_bytes()).hexdigest(), receipt["bundle_sha256"]])
print(json.dumps([old, new, rows]))
'''


def main(key=None, *, require_redaction=False):
    if key is None:
        key = fixture.setup(check_restore_path=False, lab=True)
    old, new, rows = json.loads(fixture.as_owner("/usr/bin/python3", "-IB", "-c", SEED,
                                                  str(fixture.HOME / "archive-fixture"),
                                                  "redact" if require_redaction else "original").stdout)
    ids = []
    for i, (path, manifest, bundle) in enumerate(rows):
        command = ["/usr/bin/stynpilot", "archive-adopt", "--config", str(fixture.CONFIG), "--archive", path,
                   "--manifest-sha256", manifest, "--bundle-sha256", bundle, "--client", "synthetic"]
        if i == 0:
            command += ["--client", "synthetic-other"]
        ids.append(json.loads(fixture.as_owner(*command).stdout)["archive_id"])
    pending = fixture.HOME / ".local/state/stynpilot/repository-archives/.pending-fixture_"
    fixture.as_owner("mkdir", "-m", "700", str(pending))
    fixture.as_owner("touch", str(pending / "interrupted"))
    fixture.as_owner("systemctl", "--user", "restart", "stynpilot-owner.service")
    fixture.until(lambda: endpoint_answers({"port": 18443, "host": HOST}), 20)
    assert not pending.exists()

    with httpx.Client(base_url="http://127.0.0.1:18443", timeout=30, trust_env=False, headers={"Host": HOST}) as http:
        def call(tool, *, client="fixture", **arguments):
            now = int(time.time())
            token = jwt.encode({"iss": fixture.ISSUER, "aud": "https://" + HOST + "/mcp", "sub": "fixture|test-owner",
                                "iat": now, "exp": now + 120, "azp": client, "scope": "health.read workspace.propose"},
                               key, algorithm="RS256", headers={"kid": "fixture"})
            response = http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "repository_archive_" + tool, "arguments": {"device_id": fixture.DEVICE, **arguments}}},
                headers={"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream",
                         "MCP-Protocol-Version": "2025-03-26"})
            response.raise_for_status()
            result = response.json()["result"]
            return result.get("structuredContent") or json.loads(result["content"][0]["text"])

        def ok(tool, **args):
            result = call(tool, **args)
            assert result["ok"], result
            return result["result"]

        assert sorted(a["archive_id"] for a in ok("list")["archives"]) == sorted(ids)
        assert [a["archive_id"] for a in ok("list", client="fixture-other")["archives"]] == ids[:1]
        assert ok("refs", archive_id=ids[0], limit=1)["next_offset"] == 1
        assert ok("history", archive_id=ids[0], commit=new, limit=1)["items"][0]["parents"] == [old]
        assert ok("tree", archive_id=ids[0], commit=new)["items"][0]["path"] == "README"
        historical = ok("file", archive_id=ids[0], commit=old, path="README")
        if require_redaction:
            assert historical["text"].startswith("first\n") and "only-in-old-commit" not in historical["text"]
            assert historical["redacted"] == {"secret-assignment": 1}
        else:
            assert historical["text"] == "first\n"
        pair = dict(left_archive_id=ids[0], left_commit=old, right_archive_id=ids[1], right_commit=new)
        assert ok("compare", **pair)["total"] == 1
        assert call("compare", client="fixture-other", **pair)["error"] == "archive_not_found"
        assert call("file", archive_id=ids[0], commit=new, path="../grant.json")["error"] == "archive_path_invalid"
    print("STYNPILOT_PACKAGED_ARCHIVE_MCP_OK", flush=True)


if __name__ == "__main__":
    main()
