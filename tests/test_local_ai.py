import json
import threading
import time
import unittest
from unittest.mock import patch
from stynpilot import local_ai as ai

CALLER = ("owner", "device", "client")
OTHER = ("owner", "device", "other")

class LocalAITests(unittest.TestCase):
    def test_fixed_request(self):
        b = json.loads(ai.request_body("hello"))
        self.assertEqual(b["model"], ai.MODEL)
        self.assertFalse(b["stream"])
        self.assertNotIn("tools", b)
        self.assertEqual(b["options"]["num_predict"], 512)

    def test_prompt_limit(self):
        for p in (None, "", " ", "x"*8193, "é"*4097):
            with self.assertRaises(ai.LocalAIError):
                ai.request_body(p)

    def test_result_validation(self):
        self.assertEqual(ai.parse_reply(json.dumps(
            {"done":True,"model":ai.MODEL,"response":"example"}).encode()), "example")
        for raw in (b"bad", b"[]", b"{}", b"x"*65537,
                    b'{"done":true,"model":"wrong","response":"a"}'):
            with self.assertRaises(ai.LocalAIError):
                ai.parse_reply(raw)

    def wait(self, jobs, jid, expected):
        until = time.monotonic()+3
        while time.monotonic()<until:
            result = jobs.status(CALLER, jid)
            if result["state"] == expected:
                return result
            time.sleep(.01)
        self.fail("job did not reach "+expected)

    def test_success_and_identity(self):
        jobs = ai.Jobs(lambda body,stop:"generated text")
        jid = jobs.submit(CALLER,"test")["job_id"]
        self.assertEqual(self.wait(jobs,jid,"done")["output"],"generated text")
        for f in (jobs.status,jobs.cancel):
            with self.assertRaises(ai.LocalAIError):
                f(OTHER,jid)

    def test_single_worker_cancel_and_no_late_output(self):
        release = threading.Event()
        def transport(body, stop):
            release.wait(3)
            return "discard"
        jobs = ai.Jobs(transport)
        jid = jobs.submit(CALLER,"test")["job_id"]
        try:
            with self.assertRaises(ai.LocalAIError):
                jobs.submit(OTHER,"test")
            self.assertEqual(jobs.cancel(CALLER,jid)["state"],"cancelling")
            with self.assertRaises(ai.LocalAIError):
                jobs.submit(CALLER,"test")
        finally:
            release.set()
        self.assertNotIn("output", self.wait(jobs,jid,"cancelled"))

    def test_failure_and_expiry(self):
        now = [0]
        def fail(body,stop):
            raise OSError("private diagnostic")
        jobs = ai.Jobs(fail, clock=lambda:now[0])
        jid=jobs.submit(CALLER,"test")["job_id"]
        self.assertEqual(self.wait(jobs,jid,"failed")["error"],"local_ai_unavailable")
        now[0]=ai.TTL+1
        with self.assertRaises(ai.LocalAIError):
            jobs.status(CALLER,jid)

    def test_bounded_result_storage(self):
        jobs=ai.Jobs(lambda body,stop:"ok")
        for _ in range(ai.MAX_JOBS):
            jid=jobs.submit(CALLER,"test")["job_id"]
            self.wait(jobs,jid,"done")
        with self.assertRaises(ai.LocalAIError):
            jobs.submit(CALLER,"test")

    def test_workspace_and_gate(self):
        ai.require_workspace({"gate_open":True,"workspaces":[ai.WORKSPACE]})
        for state in ({}, {"gate_open":True,"workspaces":[]},
                      {"gate_open":False,"workspaces":[ai.WORKSPACE]},
                      {"gate_open":1,"workspaces":[ai.WORKSPACE]}):
            with self.assertRaises(ai.LocalAIError):
                ai.require_workspace(state)

    @patch("stynpilot.local_ai.http.client.HTTPConnection")
    def test_fixed_transport(self, factory):
        conn = factory.return_value
        response = conn.getresponse.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = json.dumps(
            {"done":True,"model":ai.MODEL,"response":"example"}).encode()
        self.assertEqual(ai.infer(ai.request_body("test"),threading.Event()),"example")
        factory.assert_called_once_with("127.0.0.1",11435,timeout=5)
        self.assertEqual(conn.request.call_args.args[:2],("POST","/api/generate"))
        response.read.assert_called_once_with(ai.MAX_REPLY+1)
        conn.close.assert_called_once()
        response.status = 302
        with self.assertRaises(ai.LocalAIError):
            ai.infer(ai.request_body("test"),threading.Event())

    def test_durable_claim_required_before_transport(self):
        calls = []
        def transport(body,stop):
            calls.append("transport")
            return "done"
        jobs = ai.Jobs(transport, reserve=lambda jid: calls.append(("claim", jid)),
                       finish=lambda jid: calls.append(("finish", jid)))
        jid = jobs.submit(CALLER, "test")["job_id"]
        self.wait(jobs,jid,"done")
        self.assertEqual(calls,[("claim",jid),"transport",("finish",jid)])

    def test_refused_claim_never_starts_transport(self):
        def refuse(jid):
            raise ai.LocalAIError("managed_activity_busy")
        with patch("stynpilot.local_ai.infer") as transport:
            jobs=ai.Jobs(transport, reserve=refuse, finish=lambda jid:None)
            with self.assertRaises(ai.LocalAIError):
                jobs.submit(CALLER,"test")
            transport.assert_not_called()

    def test_uncertain_completion_does_not_clear_claim(self):
        claims, finished = [], []
        def fail(body,stop):
            raise OSError("ambiguous transport")
        jobs=ai.Jobs(fail,reserve=claims.append,finish=finished.append)
        jid=jobs.submit(CALLER,"test")["job_id"]
        self.wait(jobs,jid,"failed")
        self.assertEqual(claims,[jid])
        self.assertEqual(finished,[])


    def test_withdrawal_before_transport_retains_claim(self):
        claims, finished = [], []
        with patch("stynpilot.local_ai.infer") as transport:
            jobs = ai.Jobs(transport, reserve=claims.append, finish=finished.append)
            jid = jobs.submit(CALLER,"test",authorize=lambda _:False)["job_id"]
            self.assertNotIn("output",self.wait(jobs,jid,"cancelled"))
            transport.assert_not_called()
            self.assertEqual(claims,[jid])
            self.assertEqual(finished,[])

    def test_active_authorization_withdrawal_discards_output(self):
        entered, withdrawn, observed = threading.Event(), threading.Event(), threading.Event()
        finished=[]
        def transport(body,stop):
            entered.set()
            if stop.wait(3):
                observed.set()
            return "must not disclose"
        jobs=ai.Jobs(transport,reserve=lambda _:None,finish=finished.append)
        jid=jobs.submit(CALLER,"test",authorize=lambda _:not withdrawn.is_set())["job_id"]
        self.assertTrue(entered.wait(2))
        withdrawn.set()
        self.assertTrue(observed.wait(2))
        self.assertNotIn("output",self.wait(jobs,jid,"cancelled"))
        self.assertEqual(finished,[])

    def test_authority_check_failure_after_response_retains_claim(self):
        checks=[]
        finished=[]
        def authorize(jid):
            checks.append(jid)
            if len(checks)>1:
                raise OSError("unavailable")
            return True
        jobs=ai.Jobs(lambda body,stop:"late result",reserve=lambda _:None,finish=finished.append)
        jid=jobs.submit(CALLER,"test",authorize=authorize)["job_id"]
        self.assertNotIn("output",self.wait(jobs,jid,"cancelled"))
        self.assertEqual(finished,[])


    def test_worker_lease_spans_reservation_transport_and_finish(self):
        from contextlib import contextmanager
        calls=[]
        @contextmanager
        def lease():
            calls.append("lease_enter")
            try:
                yield
            finally:
                calls.append("lease_exit")
        def transport(body,stop):
            calls.append("transport")
            return "ok"
        jobs=ai.Jobs(transport, reserve=lambda _:calls.append("reserve"),
                     finish=lambda _:calls.append("finish"), worker_lease=lease)
        jid=jobs.submit(CALLER,"test")["job_id"]
        self.wait(jobs,jid,"done")
        self.assertEqual(calls,["lease_enter","reserve","transport","finish","lease_exit"])

    def test_missing_lease_prevents_reservation_and_transport(self):
        from contextlib import contextmanager
        @contextmanager
        def lease():
            raise ai.LocalAIError("inference_fence_unavailable")
            yield
        with patch("stynpilot.local_ai.infer") as transport:
            claims=[]
            jobs=ai.Jobs(transport,reserve=claims.append,finish=lambda _:None,worker_lease=lease)
            with self.assertRaises(ai.LocalAIError):
                jobs.submit(CALLER,"test")
            self.assertEqual(claims,[])
            transport.assert_not_called()
