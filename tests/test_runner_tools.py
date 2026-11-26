"""The AI-facing runner tools through the real MCP server: request setup/authorization, edit files, run and watch jobs.
Two assistants, one owner, nothing approved by an AI, nothing outside an authorized folder."""
import asyncio
import json
import os
import tempfile
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from stynpilot.identity import TokenDenied
from stynpilot.requests import RequestStore
from stynpilot.server.clients import EnrolledClients, RevocationFile
from stynpilot.server.router import LocalOwnership, ReadRouter

try:
    from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
    from mcp.server.auth.provider import AccessToken
    from stynpilot.server.app import create_server
    from stynpilot.server.diag_tools import RateLimit
except ImportError:          # pragma: no cover
    create_server = None

OWNER = "acct_" + "a" * 40
DEVICE = "dtdev_TESTONLYliveDevice"
AUDIENCE = "https://ryzen.example.test/mcp"
BOTH = frozenset({"health.read", "workspace.propose"})
NEW_TOOLS = {"commander_request_runner_setup", "commander_request_workspace_authorization", "commander_request_workspace_removal",
             "runner_status", "workspace_list", "workspace_files", "workspace_read", "jobs_list", "job_status", "job_output",
             "workspace_write", "workspace_edit", "workspace_move", "workspace_delete", "job_run", "job_cancel", "runner_selftest"}


@dataclass(frozen=True)
class Who:
    account: str
    scopes: frozenset
    client: str | None = None


class Tokens:
    issuer, audience = "https://issuer.example.test/", AUDIENCE
    valid = {"chatgpt": Who(OWNER, BOTH, "chatgpt-connector"), "claude": Who(OWNER, BOTH, "claude-connector"),
             "readonly": Who(OWNER, frozenset({"health.read"}), "claude-connector"),
             "stranger": Who("acct_" + "b" * 40, BOTH, "chatgpt-connector")}

    def authorize(self, header, required_scope):
        who = self.valid.get(header.removeprefix("Bearer "))
        if who is None or required_scope not in who.scopes:
            raise TokenDenied("denied")
        return who


class Grants:
    def get(self, *, owner_id, device_id):
        if (owner_id, device_id) != (OWNER, DEVICE):
            return None
        return SimpleNamespace(owner_id=OWNER, device_id=DEVICE, revoked=False, scopes=BOTH, expires_at=time.time() + 3600)


class Refused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class FakeBroker:
    """What the installer's GREEN socket would answer; records every call so tests can see exactly what crossed."""
    def __init__(self):
        self.calls, self.enabled, self.gate, self.workspaces, self.fail = [], False, False, [], None

    def runner(self, call, args=None):
        self.calls.append((call, dict(args or {})))
        if self.fail:
            raise Refused(self.fail)
        if call == "status":
            return {"enabled": self.enabled, "gate_open": self.gate, "workspaces": list(self.workspaces), "recipes": {"git-status": "git status"},
                    "selftest": {"ran": self.gate, "ok": self.gate}}
        if call == "workspaces":
            return {"workspaces": [{"name": w, "enrolled_at": 1} for w in self.workspaces]}
        if call == "inference_claim_status":
            return {"claim": getattr(self, "inference_claim", None)}
        if call == "inference_claim":
            self.inference_claim = {"kind": "inference", "job_id": args["job_id"]}
            return {"ok": True}
        if call == "inference_validate":
            if (not self.gate or "local-ai-pilot" not in self.workspaces or
                    getattr(self, "inference_claim", None) != {"kind": "inference", "job_id": args["job_id"]}):
                raise Refused("activity_claim_changed")
            return {"ok": True}
        if call == "inference_finish":
            self.inference_claim = None
            return {"ok": True}
        if call == "run":
            return {"job_id": "a" * 32, "argv": ["/usr/bin/git"], "limits": {}}
        return {"call": call, "args": args}


@unittest.skipIf(create_server is None, "MCP SDK not installed")
class RunnerToolTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(os.path.realpath(tmp.name))
        router = ReadRouter(tokens=Tokens(), ownership=LocalOwnership(grants=Grants(), owner_id=OWNER, device_id=DEVICE),
                            read_health=lambda: {"cpu_usage_percent": 1.0})
        state = self.tmp / "state"
        revocations = RevocationFile(state / "revoked-clients.json")
        revocations.provision()
        clients = EnrolledClients([{"client_id": "chatgpt-connector", "name": "chatgpt", "kind": "chatgpt"},
                                   {"client_id": "claude-connector", "name": "claude", "kind": "claude"}], revocations=revocations)
        self.now = [datetime(2026, 11, 22, 17, 0, 5, tzinfo=timezone.utc)]
        self.store = RequestStore(state / "requests.sqlite3", clock=lambda: self.now[0].timestamp())
        self.projects = self.tmp / "StyNpilot-Projects"
        (self.projects / "app").mkdir(parents=True)
        (self.projects / "other").mkdir()
        self.broker = FakeBroker()
        from unittest.mock import Mock
        self.readiness = Mock(return_value={"resource_checks_passed": True})
        self.limiter = RateLimit(per_minute=1000)
        self.router, self.clients = router, clients
        self.server = create_server(router=router, resource_url=AUDIENCE,
                                    propose=dict(clients=clients, store=self.store, approval_url="https://ryzen.example.test/app",
                                                 clock=lambda: self.now[0]),
                                    runner=dict(broker=self.broker, projects_dir=str(self.projects), clock=lambda: self.now[0],
                                                limiter=self.limiter, inference_readiness_probe=self.readiness))

    def call(self, name, arguments, token="chatgpt"):
        who = Tokens.valid[token]
        marker = auth_context_var.set(AuthenticatedUser(AccessToken(token=token, client_id="x", scopes=sorted(who.scopes))))
        try:
            result = asyncio.run(self.server.call_tool(name, arguments))
        finally:
            auth_context_var.reset(marker)
        if isinstance(result, tuple) and isinstance(result[1], dict) and "ok" in result[1]:
            return result[1]
        content = result[0] if isinstance(result, tuple) else result
        return json.loads(content[0].text)

    def d(self, **kw):
        return dict(device_id=DEVICE, **kw)

    def authorize(self, *names):
        self.broker.enabled, self.broker.gate = True, True
        self.broker.workspaces = list(names)

    # -- the tool list ---------------------------------------------------------------------------------
    def test_the_new_tools_are_listed_and_none_can_approve_or_run_a_free_command(self):
        names = {t.name for t in asyncio.run(self.server.list_tools())}
        self.assertTrue(NEW_TOOLS <= names)
        self.assertFalse(any(w in n for n in NEW_TOOLS for w in ("approve", "review", "execute", "shell", "sudo", "exec")))
        from stynpilot.server.propose_tools import PROPOSE_ONLY_TOOLS, RUNNER_WRITE_TOOLS
        self.assertLessEqual(RUNNER_WRITE_TOOLS, PROPOSE_ONLY_TOOLS)
        for reader in ("runner_status", "workspace_list", "workspace_files", "workspace_read", "jobs_list", "job_status", "job_output"):
            self.assertNotIn(reader, RUNNER_WRITE_TOOLS)

    # -- asking the owner --------------------------------------------------------------------------------
    def test_setup_and_authorization_requests_are_filed_for_the_owner_only(self):
        out = self.call("commander_request_runner_setup", self.d())
        self.assertTrue(out["ok"], out)
        result = out["result"]
        self.assertEqual((result["kind"], result["state"], result["approved_by_ai"]), ("runner", "pending", False))
        self.assertIn("/approve/" + result["request_id"], result["owner_approval_url"])
        self.assertIn("stynpilot-run", "\n".join(self.store.payload(result["request_id"]) and result["summary"]))
        self.assertEqual(self.call("commander_request_runner_setup", self.d(), "claude")["result"]["request_id"], result["request_id"])
        self.assertEqual([c for c in self.broker.calls if c[0] != "status"], [])          # nothing ran, nothing changed

    def test_asking_for_what_is_already_done_files_nothing(self):
        self.authorize("app")
        out = self.call("commander_request_runner_setup", self.d())
        self.assertTrue(out["ok"] and out["result"]["already_set_up"])
        self.assertEqual(self.call("commander_request_workspace_authorization", self.d(name="app"))["error"], "already_authorized")
        self.assertEqual(self.call("commander_request_workspace_removal", self.d(name="nope"))["error"], "workspace_not_authorized")

    def test_authorization_needs_setup_first_and_a_plain_name(self):
        self.assertEqual(self.call("commander_request_workspace_authorization", self.d(name="app"))["error"],
                         "runner_not_set_up_request_setup_first")
        self.broker.enabled = True
        for bad in ("../x", "a/b", ".hidden", "", "x" * 60, "a b"):
            self.assertEqual(self.call("commander_request_workspace_authorization", self.d(name=bad))["error"], "workspace_name_invalid", bad)
        ok = self.call("commander_request_workspace_authorization", self.d(name="new-app"))
        self.assertTrue(ok["ok"], ok)
        payload = self.store.payload(ok["result"]["request_id"])
        self.assertEqual((payload["kind"], payload["action"], payload["name"], payload["owner"]), ("runner", "enroll", "new-app", OWNER))

    # -- permissions -------------------------------------------------------------------------------------------
    def test_a_read_only_token_can_read_but_not_ask_edit_or_run(self):
        self.authorize("app")
        (self.projects / "app" / "a.txt").write_text("hello")
        for tool, args in (("workspace_list", {}), ("runner_status", {}), ("workspace_files", {"workspace_name": "app"}),
                           ("workspace_read", {"workspace_name": "app", "path": "a.txt"}), ("jobs_list", {}), ("job_status", {"job_id": "a" * 32})):
            self.assertTrue(self.call(tool, self.d(**args), "readonly")["ok"], tool)
        for tool, args in (("workspace_write", {"workspace_name": "app", "path": "x.txt", "content": "x"}),
                           ("workspace_edit", {"workspace_name": "app", "path": "a.txt", "old": "hello", "new": "x"}),
                           ("workspace_move", {"workspace_name": "app", "source": "a.txt", "destination": "b.txt"}),
                           ("workspace_delete", {"workspace_name": "app", "path": "a.txt"}),
                           ("job_run", {"workspace_name": "app", "recipe": "git-status"}), ("job_cancel", {"job_id": "a" * 32}),
                           ("runner_selftest", {}), ("commander_request_runner_setup", {})):
            out = self.call(tool, self.d(**args), "readonly")
            self.assertFalse(out["ok"], tool)
        self.assertEqual((self.projects / "app" / "a.txt").read_text(), "hello")
        self.assertEqual([c[0] for c in self.broker.calls if c[0] in ("run", "job_cancel", "selftest")], [])

    def test_strangers_and_unknown_devices_get_nothing(self):
        self.authorize("app")
        self.assertFalse(self.call("workspace_write", self.d(workspace_name="app", path="x.txt", content="x"), "stranger")["ok"])
        out = self.call("workspace_write", dict(device_id="dtdev_OTHER", workspace_name="app", path="x.txt", content="x"))
        self.assertFalse(out["ok"])
        self.assertFalse((self.projects / "app" / "x.txt").exists())

    # -- files ---------------------------------------------------------------------------------------------------
    def test_files_can_be_created_read_edited_moved_and_trashed_in_an_authorized_folder_only(self):
        self.authorize("app")
        w = lambda **kw: self.call("workspace_write", self.d(workspace_name="app", **kw))
        self.assertTrue(w(path="src/main.py", content="print('a')\n")["ok"])
        self.assertEqual(self.call("workspace_read", self.d(workspace_name="app", path="src/main.py"))["result"]["text"], "print('a')\n")
        self.assertTrue(self.call("workspace_edit", self.d(workspace_name="app", path="src/main.py", old="a", new="b"))["ok"])
        self.assertTrue(self.call("workspace_move", self.d(workspace_name="app", source="src/main.py", destination="main.py"))["ok"])
        self.assertTrue(self.call("workspace_delete", self.d(workspace_name="app", path="main.py"))["ok"])
        self.assertEqual([e["name"] for e in self.call("workspace_files", self.d(workspace_name="app", path="src"))["result"]["entries"]], [])
        # not authorized, not a name, not a path, not a secret
        self.assertEqual(self.call("workspace_write", self.d(workspace_name="other", path="x.txt", content="x"))["error"], "workspace_not_authorized")
        self.assertEqual(self.call("workspace_write", self.d(workspace_name="../etc", path="x.txt", content="x"))["error"], "workspace_name_invalid")
        self.assertEqual(w(path="../x.txt", content="x")["error"], "path_invalid")
        self.assertEqual(w(path=".env", content="X=1")["error"], "protected_file_name")
        self.assertEqual(w(path=".git/hooks/pre-commit", content="x")["error"], "path_is_reserved")
        self.assertEqual(os.listdir(self.projects / "other"), [])

    def test_the_installers_list_is_the_only_authority_for_a_workspace(self):
        (self.projects / "other" / "f.txt").write_text("secret-ish")
        self.broker.workspaces = ["app"]
        self.assertEqual(self.call("workspace_read", self.d(workspace_name="other", path="f.txt"))["error"], "workspace_not_authorized")
        self.broker.workspaces = ["app", "other"]
        self.assertTrue(self.call("workspace_read", self.d(workspace_name="other", path="f.txt"))["ok"])

    # -- jobs -----------------------------------------------------------------------------------------------------
    def test_jobs_cross_to_the_installer_as_names_and_recipe_words_only(self):
        self.authorize("app")
        out = self.call("job_run", self.d(workspace_name="app", recipe="git-status", args=["--x"]))
        self.assertTrue(out["ok"], out)
        self.assertEqual(self.broker.calls[-1], ("run", {"workspace": "app", "recipe": "git-status", "args": ["--x"]}))
        self.assertTrue(self.call("job_status", self.d(job_id="a" * 32))["ok"])
        self.assertTrue(self.call("job_output", self.d(job_id="a" * 32, offset=10, limit=100))["ok"])
        self.assertEqual(self.broker.calls[-1], ("job_output", {"job_id": "a" * 32, "offset": 10, "limit": 100}))
        self.assertTrue(self.call("job_cancel", self.d(job_id="a" * 32))["ok"])
        self.assertEqual(self.call("job_run", self.d(workspace_name="other", recipe="git-status"))["error"], "workspace_not_authorized")

    def test_the_installers_refusals_reach_the_assistant_in_plain_codes(self):
        self.authorize("app")
        self.broker.fail = "sandbox_self_test_required"
        self.assertEqual(self.call("job_run", self.d(workspace_name="app", recipe="git-status"))["error"], "sandbox_self_test_required")
        self.broker.fail = "installer_unavailable"
        self.assertEqual(self.call("runner_status", self.d())["error"], "installer_unavailable")

    def test_a_runaway_client_is_rate_limited(self):
        self.authorize("app")
        self.limiter.per_minute = 3
        outs = [self.call("runner_status", self.d()) for _ in range(5)]
        self.assertEqual([o["ok"] for o in outs], [True, True, True, False, False])
        self.assertEqual(outs[-1]["error"], "rate_limited_try_again_in_a_minute")


    # -- local inference: real MCP handlers, synthetic identity and model transport -------------------------------
    def test_local_ai_requires_propose_scope_device_and_open_authorized_workspace(self):
        from unittest.mock import patch
        from stynpilot.server.propose_tools import PROPOSE_ONLY_TOOLS
        tools = {"local_ai_submit", "local_ai_status", "local_ai_cancel"}
        self.assertLessEqual(tools, {t.name for t in asyncio.run(self.server.list_tools())})
        self.assertLessEqual(tools, PROPOSE_ONLY_TOOLS)
        with patch("stynpilot.local_ai.http.client.HTTPConnection") as transport:
            self.authorize("local-ai-pilot")
            for token in ("readonly", "stranger"):
                for tool, args in (("local_ai_submit", {"prompt": "test"}),
                                   ("local_ai_status", {"job_id": "x"}),
                                   ("local_ai_cancel", {"job_id": "x"})):
                    self.assertFalse(self.call(tool, self.d(**args), token)["ok"])
            self.assertFalse(self.call("local_ai_submit",
                                       dict(device_id="dtdev_OTHER", prompt="test"))["ok"])
            self.broker.gate = False
            self.assertEqual(self.call("local_ai_submit", self.d(prompt="test"))["error"],
                             "local_ai_workspace_or_gate_required")
            self.authorize("app")
            self.assertEqual(self.call("local_ai_submit", self.d(prompt="test"))["error"],
                             "local_ai_workspace_or_gate_required")
            self.authorize("local-ai-pilot")
            self.clients.revoke("chatgpt-connector")
            self.assertFalse(self.call("local_ai_submit", self.d(prompt="test"))["ok"])
            transport.assert_not_called()

    def test_local_ai_job_result_private_and_rechecks_revocation_and_workspace(self):
        from unittest.mock import patch
        from stynpilot.local_ai import MODEL
        self.authorize("local-ai-pilot")
        with patch("stynpilot.local_ai.http.client.HTTPConnection") as transport:
            reply = transport.return_value.getresponse.return_value.__enter__.return_value
            reply.status = 200
            reply.read.return_value = json.dumps(dict(done=True, model=MODEL, response="untrusted text")).encode()
            submitted = self.call("local_ai_submit", self.d(prompt="test"))
            self.assertTrue(submitted["ok"], submitted)
            jid = submitted["result"]["job_id"]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                out = self.call("local_ai_status", self.d(job_id=jid))
                self.assertTrue(out["ok"], out)
                if out["result"]["state"] != "running":
                    break
                time.sleep(.01)
            self.assertEqual(out["result"]["state"], "done", out)
            self.assertEqual(out["result"]["output"], "untrusted text")
            transport.assert_called_once_with("127.0.0.1", 11435, timeout=5)
            for tool in ("local_ai_status", "local_ai_cancel"):
                self.assertEqual(self.call(tool, self.d(job_id=jid), "claude")["error"],
                                 "local_ai_unknown_job")
                self.assertFalse(self.call(tool, self.d(job_id=jid), "readonly")["ok"])
            self.broker.gate = False
            self.assertFalse(self.call("local_ai_status", self.d(job_id=jid))["ok"])
            self.authorize("app")
            self.assertFalse(self.call("local_ai_status", self.d(job_id=jid))["ok"])
            self.authorize("local-ai-pilot")
            self.clients.revoke("chatgpt-connector")
            for tool in ("local_ai_status", "local_ai_cancel"):
                self.assertFalse(self.call(tool, self.d(job_id=jid))["ok"])

    def test_local_ai_cancel_while_workspace_removed(self):
        import threading
        from unittest.mock import patch
        self.authorize("local-ai-pilot")
        entered, release = threading.Event(), threading.Event()
        with patch("stynpilot.local_ai.http.client.HTTPConnection") as transport:
            reply = transport.return_value.getresponse.return_value.__enter__.return_value
            reply.status = 200
            def read(_):
                entered.set()
                release.wait(5)
                from stynpilot.local_ai import MODEL
                return json.dumps(dict(done=True, model=MODEL, response="late text")).encode()
            reply.read.side_effect = read
            submitted = self.call("local_ai_submit", self.d(prompt="test"))
            self.assertTrue(submitted["ok"], submitted)
            jid = submitted["result"]["job_id"]
            try:
                self.assertTrue(entered.wait(3))
                self.authorize("app")
                self.assertFalse(self.call("local_ai_status", self.d(job_id=jid))["ok"])
                self.assertFalse(self.call("local_ai_cancel", self.d(job_id=jid), "claude")["ok"])
                cancelled = self.call("local_ai_cancel", self.d(job_id=jid))
                self.assertEqual(cancelled["result"]["state"], "cancelling")
            finally:
                release.set()
            self.authorize("local-ai-pilot")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                out = self.call("local_ai_status", self.d(job_id=jid))
                self.assertTrue(out["ok"], out)
                if out["result"]["state"] == "cancelled":
                    break
                time.sleep(.01)
            self.assertEqual(out["result"]["state"], "cancelled", out)
            self.assertNotIn("output", out["result"])

    def test_local_ai_containment_gate_and_readiness(self):
        from unittest.mock import patch
        self.authorize("local-ai-pilot")
        self.readiness.return_value = {"resource_checks_passed": False}
        report = self.call("local_ai_readiness", self.d(), "readonly")
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["result"]["resource_checks_passed"])
        with patch("stynpilot.local_ai.http.client.HTTPConnection") as transport:
            out = self.call("local_ai_submit", self.d(prompt="test"))
            self.assertEqual(out["error"], "local_ai_containment_required")
            transport.assert_not_called()
        self.assertFalse(self.call("local_ai_readiness", self.d(), "stranger")["ok"])

    def test_settlement_only_requests_owner_approval(self):
        tool = "commander_request_local_ai_settlement"
        self.assertTrue(self.call(tool, self.d())["result"]["already_idle"])
        self.broker.inference_claim = {"kind": "inference", "job_id": "a"*32}
        self.assertFalse(self.call(tool, self.d(), "readonly")["ok"])
        self.assertFalse(self.call(tool, self.d(), "stranger")["ok"])
        result = self.call(tool, self.d())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"]["state"], "pending")
        payload = self.store.payload(result["result"]["request_id"])
        self.assertEqual((payload["kind"], payload["action"], payload["name"]),
                         ("runner", "settle_inference", "a"*32))
        self.assertTrue(all(call == "inference_claim_status" for call, args in self.broker.calls))

    def test_active_inference_withdrawal_is_observed_without_status_polling(self):
        import threading
        from unittest.mock import patch
        from stynpilot.local_ai import MODEL
        for action in ("revoke", "remove_workspace", "lose_claim"):
            self.authorize("local-ai-pilot")
            self.clients.reinstate("chatgpt-connector")
            entered, interrupted, release = threading.Event(), threading.Event(), threading.Event()
            with patch("stynpilot.local_ai.http.client.HTTPConnection") as transport:
                conn = transport.return_value
                reply = conn.getresponse.return_value.__enter__.return_value
                reply.status = 200
                def shutdown(_):
                    interrupted.set()
                    release.set()
                conn.sock.shutdown.side_effect = shutdown
                def read(_):
                    entered.set()
                    release.wait(5)
                    return json.dumps(dict(done=True,model=MODEL,response="discard")).encode()
                reply.read.side_effect = read
                result=self.call("local_ai_submit",self.d(prompt="test"))
                self.assertTrue(result["ok"],result)
                jid=result["result"]["job_id"]
                try:
                    self.assertTrue(entered.wait(3))
                    if action=="revoke":
                        self.clients.revoke("chatgpt-connector")
                    elif action=="remove_workspace":
                        self.authorize("app")
                    else:
                        self.broker.inference_claim=None
                    self.assertTrue(interrupted.wait(3),action)
                finally:
                    release.set()
                self.clients.reinstate("chatgpt-connector")
                self.authorize("local-ai-pilot")
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    out=self.call("local_ai_status",self.d(job_id=jid))
                    if out["ok"] and out["result"]["state"]=="cancelled":
                        break
                    time.sleep(.01)
                self.assertEqual(out["result"]["state"],"cancelled",out)
                self.assertNotIn("output",out["result"])
                self.assertFalse(any(call=="inference_finish" and args.get("job_id")==jid for call,args in self.broker.calls))


if __name__ == "__main__":
    unittest.main()
