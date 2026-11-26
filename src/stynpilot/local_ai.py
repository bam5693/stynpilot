"""Bounded, text-only local inference jobs. No tools or generated code execution."""
from __future__ import annotations

import http.client
import json
import secrets
import socket
import threading
import time

MODEL = "qwen2.5-coder:7b"
WORKSPACE = "local-ai-pilot"
MAX_PROMPT = 8192
MAX_REPLY = 65536
MAX_JOBS = 8
TTL = 600
DEADLINE = 240


class LocalAIError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require_workspace(state):
    if (type(state) is not dict or state.get("gate_open") is not True
            or type(state.get("workspaces")) is not list
            or WORKSPACE not in state["workspaces"]):
        raise LocalAIError("local_ai_workspace_or_gate_required")


def request_body(prompt):
    if type(prompt) is not str or not prompt.strip() or len(prompt.encode("utf-8")) > MAX_PROMPT:
        raise LocalAIError("local_ai_invalid_prompt")
    return json.dumps({
        "model": MODEL, "prompt": prompt, "stream": False,
        "keep_alive": "0s",
        "options": {"num_ctx": 4096, "num_predict": 512},
    }).encode("utf-8")


def parse_reply(raw):
    if len(raw) > MAX_REPLY:
        raise LocalAIError("local_ai_reply_too_large")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise LocalAIError("local_ai_invalid_reply") from None
    if (type(data) is not dict or data.get("done") is not True
            or data.get("model") != MODEL or type(data.get("response")) is not str):
        raise LocalAIError("local_ai_invalid_reply")
    return data["response"]


def infer(body, stop):
    # Never accept an endpoint, model, headers, tools, or a command from a caller.
    conn = http.client.HTTPConnection("127.0.0.1", 11435, timeout=5)
    interrupted = threading.Event()
    try:
        if stop.is_set():
            raise LocalAIError("local_ai_cancelled")
        conn.connect()
        sock = conn.sock
        sock.settimeout(DEADLINE)
        finished = threading.Event()

        def watch():
            end = time.monotonic() + DEADLINE
            while not finished.wait(0.1):
                if stop.is_set() or time.monotonic() >= end:
                    interrupted.set()
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return

        monitor = threading.Thread(target=watch, daemon=True)
        monitor.start()
        try:
            if stop.is_set():
                raise LocalAIError("local_ai_cancelled")
            conn.request("POST", "/api/generate", body=body,
                         headers={"Content-Type": "application/json"})
            with conn.getresponse() as response:
                if response.status != 200:
                    raise LocalAIError("local_ai_endpoint_refused")
                result = parse_reply(response.read(MAX_REPLY + 1))
            if interrupted.is_set():
                raise LocalAIError("local_ai_interrupted")
            return result
        finally:
            finished.set()
            monitor.join()
    finally:
        conn.close()


class Jobs:
    """One active request globally. Volatile, bounded, caller-scoped results."""
    def __init__(self, transport=infer, clock=time.monotonic):
        self._transport = transport
        self._clock = clock
        self._lock = threading.Lock()
        self._jobs = {}
        self._active = None

    def _prune(self):
        now = self._clock()
        for jid, row in list(self._jobs.items()):
            if row["finished"] is not None and now - row["finished"] >= TTL:
                del self._jobs[jid]

    def submit(self, caller, prompt):
        body = request_body(prompt)
        with self._lock:
            self._prune()
            if self._active is not None:
                raise LocalAIError("local_ai_busy")
            if len(self._jobs) >= MAX_JOBS:
                raise LocalAIError("local_ai_results_full")
            jid = secrets.token_hex(16)
            row = {"caller": caller, "state": "running", "stop": threading.Event(),
                   "finished": None, "output": None, "error": None}
            self._jobs[jid] = row
            self._active = jid
            worker = threading.Thread(target=self._run, args=(jid, row, body), daemon=True)
            try:
                worker.start()
            except Exception:
                del self._jobs[jid]
                self._active = None
                raise LocalAIError("local_ai_start_failed") from None
            return {"job_id": jid, "state": "running", "model": MODEL}

    def _run(self, jid, row, body):
        output, error = None, "local_ai_unavailable"
        try:
            output = self._transport(body, row["stop"])
            error = None
            if type(output) is not str or len(output.encode("utf-8")) > MAX_REPLY:
                output, error = None, "local_ai_invalid_reply"
        except LocalAIError as exc:
            error = exc.code
        except Exception:
            error = "local_ai_unavailable"
        finally:
            with self._lock:
                if row["stop"].is_set():
                    row["state"] = "cancelled"
                elif error is not None:
                    row["state"], row["error"] = "failed", error
                else:
                    row["state"], row["output"] = "done", output
                row["finished"] = self._clock()
                self._active = None

    def _owned(self, caller, jid):
        self._prune()
        row = self._jobs.get(jid) if type(jid) is str else None
        if row is None or row["caller"] != caller:
            raise LocalAIError("local_ai_unknown_job")
        return row

    def status(self, caller, jid):
        with self._lock:
            row = self._owned(caller, jid)
            result = {"job_id": jid, "state": row["state"], "model": MODEL}
            if row["state"] == "done":
                result["output"] = row["output"]
                result["note"] = "Untrusted model text; not executed."
            if row["error"]:
                result["error"] = row["error"]
            return result

    def cancel(self, caller, jid):
        with self._lock:
            row = self._owned(caller, jid)
            if row["state"] == "running":
                row["stop"].set()
                row["state"] = "cancelling"
            return {"job_id": jid, "state": row["state"]}
