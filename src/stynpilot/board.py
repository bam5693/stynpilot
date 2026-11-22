"""Shared task board for several AI workers: coordinate, never authorize.

Each assistant (ChatGPT, Claude, a local model) is a separate identity keyed by the
verified OAuth client id of its own token. The owner enrolls identities; assistants
cannot enroll or reinstate anyone. The board records who works on what:

* tasks name exact claims (path:, branch:, mr:, pr:, issue:); overlapping active claims are refused;
* the same active title in one project is refused as duplicate work;
* a worker claims only tasks assigned to it and holds a fenced lease; a stale worker
  cannot overwrite a recovered or withdrawn task;
* every identity has its own rate limit, open-task cap, project list and audit events;
* revoking one identity blocks its tasks and releases its claims without touching others.

Review flow (new in this repository):
* a ``review`` task points at a FINISHED parent task and a ``commit:<sha>``; new commits need
  a new review. The board checks only the shape of that SHA, not that it is the PR head or
  who wrote it, so a verdict is a record of what the reviewer says they checked;
* the assistant that did the work cannot review it under any of its identities; the
  coordinator that only wrote the task can;
* a review finishes with a verdict (approve, approve-with-changes or object) and evidence;
* reviews are ADVISORY records for the owner. Nothing in StyNpilot treats a verdict as an
  approval or as permission to merge or run anything; the owner decides;
* at most MAX_REVIEW_ROUNDS reviews per parent (first review plus two rebuttals); after
  that the assistants must hand the owner one decision question instead of looping;
* tasks created under other tasks may nest only MAX_DEPTH levels deep.

Cancellation: ``withdraw`` moves a task to ``cancelled`` and drops its lease, so the
worker's next ``progress`` call gets ``lease_lost``. That is the runner's signal to stop.

A task grants NO permission and runs nothing. Whatever a worker does still passes the
GREEN/YELLOW/BLACK checks and the owner's approvals. Task descriptions and instructions
are untrusted text: only the assignee receives them, and they are marked untrusted.

Migrated from the GitLab prototype (src/commander_coordination.py) with its tests.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path

LEASE_SECONDS = 600
MAX_ATTEMPTS = 2
MAX_PENDING_INSTRUCTIONS = 5
MAX_REVIEW_ROUNDS = 3
MAX_DEPTH = 2
RATE_WINDOW = 60
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
CLIENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}")
CLAIM = re.compile(r"(path|branch|mr|pr|issue):[A-Za-z0-9._/@-]{1,160}")
REF = re.compile(r"(issue|mr|pr|branch):[A-Za-z0-9._/#!@-]{1,160}|commit:[0-9a-f]{40}")
COMMIT_REF = re.compile(r"commit:[0-9a-f]{40}")
TASK_ID = re.compile(r"[0-9a-f]{16}")
KINDS = ("chatgpt", "claude", "local")
TASK_KINDS = ("work", "review")
VERDICTS = ("approve", "approve-with-changes", "object")
ACTIVE = ("queued", "running")
SCHEMA = """
CREATE TABLE IF NOT EXISTS assistants(client_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
  projects TEXT NOT NULL, can_assign INTEGER NOT NULL, max_open INTEGER NOT NULL,
  rate_per_minute INTEGER NOT NULL, enabled INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(task_id TEXT PRIMARY KEY, project TEXT NOT NULL, title TEXT NOT NULL,
  norm_title TEXT NOT NULL, description TEXT NOT NULL, creator TEXT NOT NULL, assignee TEXT NOT NULL,
  priority INTEGER NOT NULL, state TEXT NOT NULL, claims TEXT NOT NULL, ref TEXT, attempts INTEGER NOT NULL,
  lease_id TEXT, lease_deadline REAL, progress INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT '', created REAL NOT NULL, updated REAL NOT NULL,
  task_kind TEXT NOT NULL DEFAULT 'work', parent_task_id TEXT, review_round INTEGER NOT NULL DEFAULT 0,
  depth INTEGER NOT NULL DEFAULT 0, verdict TEXT);
CREATE INDEX IF NOT EXISTS tasks_active ON tasks(project, state);
CREATE INDEX IF NOT EXISTS tasks_parent ON tasks(parent_task_id);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL,
  event TEXT NOT NULL, task_id TEXT, detail TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS events_actor ON events(actor, ts);
CREATE TABLE IF NOT EXISTS instructions(id TEXT PRIMARY KEY, task_id TEXT NOT NULL, from_client TEXT NOT NULL,
  text TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL, delivered REAL);
CREATE INDEX IF NOT EXISTS instructions_task ON instructions(task_id, state);
"""


class Denied(Exception):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code, self.detail = code, detail


def _name(value):
    if type(value) is not str or not NAME.fullmatch(value):
        raise Denied("bad_name")
    return value


def _text(value, limit, *, multiline=False, empty=False):
    if type(value) is not str or len(value) > limit or (not value.strip() and not empty):
        raise Denied("bad_text")
    if any(ord(c) < 32 and not (multiline and c in "\n\t") or ord(c) == 127 for c in value):
        raise Denied("bad_text")
    return value.strip()


def _int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Denied("bad_number")
    return value


def _claim(value):
    if type(value) is not str or not CLAIM.fullmatch(value):
        raise Denied("bad_claim")
    kind, _, body = value.partition(":")
    if kind == "path":
        parts = body.strip("/").split("/")
        if body.startswith("/") or any(p in ("", ".", "..") for p in parts):
            raise Denied("bad_claim")
        body = "/".join(parts)
    return kind, body


def _overlap(a, b):
    if a[0] != b[0]:
        return False
    if a[0] == "path":
        return a[1] == b[1] or a[1].startswith(b[1] + "/") or b[1].startswith(a[1] + "/")
    return a[1] == b[1]


class Board:
    def __init__(self, path, *, clock=time.time):
        if not callable(clock):
            raise ValueError("Clock required")
        self.path, self.clock, self._lock = Path(path), clock, threading.RLock()
        # The folder must be private too: otherwise another account could swap the file
        # between this check and SQLite opening it.
        parent = os.lstat(self.path.parent)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise ValueError("Task board folder must be owned by this account and not group/world writable")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("Private task board file required (mode 0600, owned by this account)")
        finally:
            os.close(fd)
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        try:
            db.executescript(SCHEMA)
        finally:
            db.close()

    @contextmanager
    def _tx(self):
        with self._lock:
            db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                db.execute("BEGIN IMMEDIATE")
                try:
                    yield db
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
                db.execute("COMMIT")
            finally:
                db.close()

    # -- owner-only administration (never exposed as an assistant tool) -------------------
    def enroll_assistant(self, client_id, name, kind, projects, *, can_assign=False, max_open=5,
                         rate_per_minute=20):
        if type(client_id) is not str or not CLIENT.fullmatch(client_id) or kind not in KINDS:
            raise ValueError("Valid client id and kind required")
        if type(projects) not in (list, tuple) or not 1 <= len(projects) <= 16:
            raise ValueError("One to sixteen projects required")
        try:
            row = (client_id, _name(name), kind, json.dumps(sorted({_name(p) for p in projects})),
                   1 if can_assign is True else 0, _int(max_open, 1, 20), _int(rate_per_minute, 1, 120), 1)
            with self._tx() as db:
                db.execute("INSERT INTO assistants VALUES(?,?,?,?,?,?,?,?)", row)
                self._event(db, "owner", "enroll", None, name)
        except (Denied, sqlite3.IntegrityError):
            raise ValueError("Invalid or duplicate assistant") from None

    def revoke_assistant(self, client_id):
        """Disable one identity. Its tasks are blocked and their claims released; others are untouched."""
        now = self.clock()
        with self._tx() as db:
            if db.execute("UPDATE assistants SET enabled=0 WHERE client_id=?", (client_id,)).rowcount != 1:
                raise ValueError("Unknown assistant")
            blocked = db.execute("""UPDATE tasks SET state='blocked',lease_id=NULL,lease_deadline=NULL,updated=?
                WHERE assignee=? AND state IN ('queued','running')""", (now, client_id)).rowcount
            db.execute("UPDATE instructions SET state='void' WHERE from_client=? AND state IN ('pending','delivered')",
                       (client_id,))
            self._event(db, "owner", "revoke", None, "blocked=%d" % blocked)
        return blocked

    def reinstate_assistant(self, client_id):
        with self._tx() as db:
            if db.execute("UPDATE assistants SET enabled=1 WHERE client_id=?", (client_id,)).rowcount != 1:
                raise ValueError("Unknown assistant")
            self._event(db, "owner", "reinstate", None)

    def audit(self, actor=None, limit=100):
        """Owner view of events (no task text). Optionally one identity's own events."""
        limit = _int(limit, 1, 1000)
        with self._tx() as db:
            if actor is None:
                rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
            else:
                rows = db.execute("SELECT * FROM events WHERE actor=? ORDER BY id DESC LIMIT ?", (actor, limit))
            return [dict(r) for r in rows.fetchall()]

    # -- helpers ---------------------------------------------------------------------------
    def _event(self, db, actor, event, task_id, detail=""):
        db.execute("INSERT INTO events(ts,actor,event,task_id,detail) VALUES(?,?,?,?,?)",
                   (self.clock(), actor, event, task_id, detail[:200]))

    def _light(self, db, actor, event):
        """Count a read or empty poll against the rate limit; these rows expire after an hour."""
        self._event(db, actor, event, None)
        db.execute("DELETE FROM events WHERE event IN ('read','claim_empty') AND ts<?", (self.clock() - 3600,))

    def _me(self, db, client_id, project=None):
        row = db.execute("SELECT * FROM assistants WHERE client_id=?", (client_id,)).fetchone() \
            if type(client_id) is str else None
        if row is None or not row["enabled"]:
            raise Denied("unknown_or_revoked")
        me = dict(row, projects=json.loads(row["projects"]))
        if project is not None and project not in me["projects"]:
            raise Denied("project_not_authorized")
        return me

    def _rate(self, db, me):
        count = db.execute("SELECT COUNT(*) FROM events WHERE actor=? AND ts>?",
                           (me["client_id"], self.clock() - RATE_WINDOW)).fetchone()[0]
        if count >= me["rate_per_minute"]:
            raise Denied("rate_limited")

    def _recover(self, db):
        now = self.clock()
        for row in db.execute("SELECT task_id,attempts FROM tasks WHERE state='running' AND lease_deadline<=?",
                              (now,)).fetchall():
            state = "queued" if row["attempts"] < MAX_ATTEMPTS else "blocked"
            db.execute("UPDATE tasks SET state=?,lease_id=NULL,lease_deadline=NULL,updated=? WHERE task_id=?",
                       (state, now, row["task_id"]))
            self._event(db, "system", "lease_expired", row["task_id"], state)

    def _row(self, db, task_id):
        return db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()

    def _view(self, db, row, *, with_description=False, lease=False):
        names = {r["client_id"]: r["name"] for r in db.execute("SELECT client_id,name FROM assistants")}
        view = {"task_id": row["task_id"], "project": row["project"], "title": row["title"],
                "kind": row["task_kind"], "parent_task_id": row["parent_task_id"],
                "state": row["state"], "priority": row["priority"], "assignee": names.get(row["assignee"]),
                "created_by": names.get(row["creator"]), "claims": json.loads(row["claims"]),
                "ref": row["ref"], "progress": row["progress"], "note": row["note"],
                "attempts": row["attempts"], "grants_no_permissions": True, "executed": False}
        if row["task_kind"] == "review":
            view["review_round"] = row["review_round"]
            view["verdict"] = row["verdict"]
        if row["state"] in ("done", "failed"):
            view["result"] = row["result"]
        if with_description:
            view["description"] = row["description"]
            view["description_is_untrusted_text"] = True
        if lease:
            view["lease_id"] = row["lease_id"]
            view["lease_seconds"] = LEASE_SECONDS
        return view

    def _deliver(self, db, task_id):
        """Checkpoint delivery: unacknowledged instructions, oldest first. At-least-once until acked."""
        now, out = self.clock(), []
        for r in db.execute("SELECT * FROM instructions WHERE task_id=? AND state IN ('pending','delivered') "
                            "ORDER BY created,rowid", (task_id,)).fetchall():
            db.execute("UPDATE instructions SET state='delivered',delivered=COALESCE(delivered,?) WHERE id=?",
                       (now, r["id"]))
            out.append({"instruction_id": r["id"], "text": r["text"], "instruction_is_untrusted_text": True,
                        "grants_no_permissions": True, "must_ack": True})
        return out

    def _void(self, db, task_id):
        db.execute("UPDATE instructions SET state='void' WHERE task_id=? AND state IN ('pending','delivered')",
                   (task_id,))

    def _run(self, client_id, event, body):
        """Run an operation; record a refusal against the caller's own audit trail."""
        try:
            with self._tx() as db:
                return body(db)
        except Denied as error:
            if error.code != "unknown_or_revoked":
                try:
                    with self._tx() as db:
                        if db.execute("SELECT 1 FROM assistants WHERE client_id=? AND enabled=1",
                                      (client_id,)).fetchone():
                            self._event(db, client_id, "refused:" + event, None, error.code)
                except Exception:
                    pass
            raise

    def _lineage(self, db, proj, kind, parent_task_id, target_id, ref):
        """Return (depth, review_round) for a new task, enforcing the review and nesting rules."""
        if parent_task_id is None:
            if kind == "review":
                raise Denied("review_needs_parent")
            return 0, 0
        if type(parent_task_id) is not str or not TASK_ID.fullmatch(parent_task_id):
            raise Denied("bad_parent")
        parent = self._row(db, parent_task_id)
        if parent is None or parent["project"] != proj:
            raise Denied("bad_parent")
        depth = parent["depth"] + 1
        if depth > MAX_DEPTH:
            raise Denied("delegation_too_deep")
        if kind != "review":
            return depth, 0
        if parent["task_kind"] == "review":
            raise Denied("cannot_review_a_review")
        if parent["state"] != "done":
            raise Denied("review_needs_finished_work")
        if not (type(ref) is str and COMMIT_REF.fullmatch(ref)):
            raise Denied("review_needs_exact_commit_ref")
        # The assistant that did the work may not review it, under any of its identities (for
        # example the Claude app and the Claude runner). The task's creator MAY review: a
        # coordinator that wrote the task and wrote no code is a valid independent reviewer.
        # The board cannot see real Git authorship, so this is a sanity rule on board roles,
        # not proof of authorship. Verdicts stay advisory (see module docstring).
        if target_id == parent["assignee"]:
            raise Denied("reviewer_must_differ_from_author")
        kinds = dict(db.execute("SELECT client_id,kind FROM assistants WHERE client_id IN (?,?)",
                                (target_id, parent["assignee"])).fetchall())
        if kinds.get(target_id) == kinds.get(parent["assignee"]):
            raise Denied("reviewer_must_be_a_different_assistant")
        rounds = db.execute("SELECT COUNT(*) FROM tasks WHERE parent_task_id=? AND task_kind='review'",
                            (parent_task_id,)).fetchone()[0]
        if rounds >= MAX_REVIEW_ROUNDS:
            raise Denied("review_rounds_exhausted_ask_owner")
        return depth, rounds + 1

    # -- assistant operations -------------------------------------------------------------
    def create(self, client_id, project, title, *, description="", assignee=None, claims=(), priority=3,
               ref=None, kind="work", parent_task_id=None):
        def body(db):
            proj = _name(project)
            me = self._me(db, client_id, proj)
            self._rate(db, me)
            head = _text(title, 120)
            text = _text(description, 2000, multiline=True, empty=True)
            level = _int(priority, 1, 5)
            if kind not in TASK_KINDS:
                raise Denied("bad_kind")
            if ref is not None and (type(ref) is not str or not REF.fullmatch(ref)):
                raise Denied("bad_ref")
            if type(claims) not in (list, tuple) or len(claims) > 8:
                raise Denied("bad_claim")
            parsed = [_claim(c) for c in claims]
            target_id = assignee if assignee is not None else client_id
            if target_id != client_id and not me["can_assign"]:
                raise Denied("not_allowed_to_assign")
            try:
                target = self._me(db, target_id, proj)
            except Denied:
                raise Denied("assignee_unavailable") from None
            depth, review_round = self._lineage(db, proj, kind, parent_task_id, target_id, ref)
            self._recover(db)
            if db.execute("SELECT COUNT(*) FROM tasks WHERE assignee=? AND state IN ('queued','running')",
                          (target_id,)).fetchone()[0] >= target["max_open"]:
                raise Denied("too_many_open_tasks")
            norm = " ".join(head.lower().split())
            conflicts = []
            for row in db.execute("SELECT * FROM tasks WHERE project=? AND state IN ('queued','running')", (proj,)):
                if row["norm_title"] == norm:
                    raise Denied("duplicate_work", [row["task_id"]])
                for old in json.loads(row["claims"]):
                    if any(_overlap(_claim(old), new) for new in parsed):
                        conflicts.append({"task_id": row["task_id"], "claim": old})
            if conflicts:
                raise Denied("conflict", conflicts)
            task_id, now = secrets.token_hex(8), self.clock()
            stored = sorted({"%s:%s" % c for c in parsed})
            db.execute("""INSERT INTO tasks(task_id,project,title,norm_title,description,creator,assignee,priority,
                state,claims,ref,attempts,created,updated,task_kind,parent_task_id,review_round,depth)
                VALUES(?,?,?,?,?,?,?,?,'queued',?,?,0,?,?,?,?,?,?)""",
                       (task_id, proj, head, norm, text, client_id, target_id, level, json.dumps(stored), ref,
                        now, now, kind, parent_task_id, review_round, depth))
            self._event(db, client_id, "create", task_id, "assignee=%s kind=%s" % (target["name"], kind))
            return self._view(db, self._row(db, task_id))
        return self._run(client_id, "create", body)

    def claim(self, client_id):
        """Take this identity's highest-priority queued task. Returns None when there is nothing to do."""
        def body(db):
            me = self._me(db, client_id)
            self._rate(db, me)
            self._recover(db)
            if db.execute("SELECT 1 FROM tasks WHERE assignee=? AND state='running'", (client_id,)).fetchone():
                raise Denied("already_running_a_task")
            marks = ",".join("?" * len(me["projects"]))
            row = db.execute("SELECT * FROM tasks WHERE assignee=? AND state='queued' AND project IN (%s) "
                             "ORDER BY priority,created,rowid LIMIT 1" % marks,
                             (client_id, *me["projects"])).fetchone()
            if row is None:
                self._light(db, client_id, "claim_empty")
                return None
            lease, now = secrets.token_hex(8), self.clock()
            db.execute("UPDATE tasks SET state='running',attempts=attempts+1,lease_id=?,lease_deadline=?,updated=? "
                       "WHERE task_id=? AND state='queued'", (lease, now + LEASE_SECONDS, now, row["task_id"]))
            self._event(db, client_id, "claim", row["task_id"])
            view = self._view(db, self._row(db, row["task_id"]), with_description=True, lease=True)
            view["instructions"] = self._deliver(db, row["task_id"])
            return view
        return self._run(client_id, "claim", body)

    def _fenced(self, db, client_id, task_id, lease_id):
        me = self._me(db, client_id)
        self._rate(db, me)
        self._recover(db)
        row = self._row(db, task_id) if type(task_id) is str else None
        if row is None or row["assignee"] != client_id:
            raise Denied("unknown_task")
        if (row["state"] != "running" or type(lease_id) is not str or not lease_id
                or not secrets.compare_digest(str(row["lease_id"]), lease_id)):
            raise Denied("lease_lost")
        return row

    def progress(self, client_id, task_id, lease_id, percent, note=""):
        def body(db):
            self._fenced(db, client_id, task_id, lease_id)
            pct, text, now = _int(percent, 0, 100), _text(note, 300, empty=True), self.clock()
            db.execute("UPDATE tasks SET progress=?,note=?,lease_deadline=?,updated=? WHERE task_id=?",
                       (pct, text, now + LEASE_SECONDS, now, task_id))
            self._event(db, client_id, "progress", task_id, str(pct))
            view = self._view(db, self._row(db, task_id))
            view["instructions"] = self._deliver(db, task_id)
            return view
        return self._run(client_id, "progress", body)

    def finish(self, client_id, task_id, lease_id, outcome, summary="", *, verdict=None):
        def body(db):
            row = self._fenced(db, client_id, task_id, lease_id)
            if outcome not in ("done", "failed"):
                raise Denied("bad_outcome")
            if row["task_kind"] == "review" and outcome == "done":
                if verdict not in VERDICTS:
                    raise Denied("review_needs_verdict")
                if not (type(summary) is str and summary.strip()):
                    raise Denied("review_needs_evidence")
            elif verdict is not None:
                raise Denied("verdict_only_for_finished_reviews")
            text, now = _text(summary, 1000, multiline=True, empty=True), self.clock()
            # Follow-ups that were never acknowledged are voided below. Say so in the result
            # itself, so a late instruction can never disappear silently (even one that
            # arrived a moment before this call, after the worker's last checkpoint).
            unapplied = db.execute("SELECT COUNT(*) FROM instructions WHERE task_id=? AND state IN "
                                   "('pending','delivered')", (task_id,)).fetchone()[0]
            if unapplied:
                note = (" [%d follow-up instruction(s) were not applied before this task finished; "
                        "send them as a new task.]" % unapplied)
                text = text[:1000 - len(note)].rstrip() + note
            db.execute("UPDATE tasks SET state=?,result=?,verdict=?,lease_id=NULL,lease_deadline=NULL,progress=?,"
                       "updated=? WHERE task_id=?",
                       (outcome, text, verdict, 100 if outcome == "done" else row["progress"], now, task_id))
            self._void(db, task_id)
            self._event(db, client_id, "finish", task_id, outcome if verdict is None else outcome + ":" + verdict)
            view = self._view(db, self._row(db, task_id))
            view["unapplied_instructions"] = unapplied
            return view
        return self._run(client_id, "finish", body)

    def still_leased(self, client_id, task_id, lease_id):
        """Cheap cancellation probe: is this lease still mine and running?

        Exempt from the rate limit on purpose, so a worker can notice an owner's withdraw
        within seconds. It is safe to exempt: it reads only the caller's own lease, returns
        a single boolean, writes nothing, and changes nothing.
        """
        if not all(type(v) is str and v for v in (client_id, task_id, lease_id)):
            return False
        with self._tx() as db:
            me = db.execute("SELECT enabled FROM assistants WHERE client_id=?", (client_id,)).fetchone()
            if me is None or not me["enabled"]:
                return False
            row = db.execute("SELECT assignee,state,lease_id,lease_deadline FROM tasks WHERE task_id=?",
                             (task_id,)).fetchone()
        return bool(row is not None and row["assignee"] == client_id and row["state"] == "running"
                    and row["lease_id"] == lease_id and (row["lease_deadline"] or 0) > self.clock())

    def withdraw(self, client_id, task_id):
        """Cancel a task. Only its creator or assignee may. The worker's next checkpoint gets lease_lost."""
        def body(db):
            me = self._me(db, client_id)
            self._rate(db, me)
            row = self._row(db, task_id) if type(task_id) is str else None
            if row is None or row["project"] not in me["projects"]:
                raise Denied("unknown_task")
            if client_id not in (row["creator"], row["assignee"]):
                raise Denied("not_owner_of_task")
            if row["state"] not in ACTIVE:
                raise Denied("task_not_active")
            db.execute("UPDATE tasks SET state='cancelled',lease_id=NULL,lease_deadline=NULL,updated=? "
                       "WHERE task_id=?", (self.clock(), task_id))
            self._void(db, task_id)
            self._event(db, client_id, "withdraw", task_id)
            return self._view(db, self._row(db, task_id))
        return self._run(client_id, "withdraw", body)

    def instruct(self, client_id, task_id, text):
        """Queue a follow-up for a task. Delivered at the assignee's next claim or progress
        checkpoint; never interrupts. Untrusted text that grants nothing."""
        def body(db):
            me = self._me(db, client_id)
            self._rate(db, me)
            note = _text(text, 1000, multiline=True)
            row = self._row(db, task_id) if type(task_id) is str else None
            if row is None or row["project"] not in me["projects"]:
                raise Denied("unknown_task")
            if client_id not in (row["creator"], row["assignee"]) and not me["can_assign"]:
                raise Denied("not_allowed_to_instruct")
            self._recover(db)
            if self._row(db, task_id)["state"] not in ACTIVE:
                raise Denied("task_not_active")
            if db.execute("SELECT COUNT(*) FROM instructions WHERE task_id=? AND state IN ('pending','delivered')",
                          (task_id,)).fetchone()[0] >= MAX_PENDING_INSTRUCTIONS:
                raise Denied("too_many_pending_instructions")
            iid = secrets.token_hex(8)
            db.execute("INSERT INTO instructions VALUES(?,?,?,?,'pending',?,NULL)",
                       (iid, task_id, client_id, note, self.clock()))
            self._event(db, client_id, "instruct", task_id)
            return {"instruction_id": iid, "state": "queued_for_next_checkpoint", "grants_no_permissions": True}
        return self._run(client_id, "instruct", body)

    def ack(self, client_id, task_id, lease_id, instruction_id):
        def body(db):
            self._fenced(db, client_id, task_id, lease_id)
            if db.execute("UPDATE instructions SET state='acknowledged' WHERE id=? AND task_id=? "
                          "AND state='delivered'", (instruction_id, task_id)).rowcount != 1:
                raise Denied("unknown_instruction")
            self._event(db, client_id, "ack", task_id)
            return {"instruction_id": instruction_id, "state": "acknowledged"}
        return self._run(client_id, "ack", body)

    def list_tasks(self, client_id, project, *, include_finished=False):
        def body(db):
            proj = _name(project)
            me = self._me(db, client_id, proj)
            self._rate(db, me)
            self._light(db, client_id, "read")
            self._recover(db)
            marks = "" if include_finished else " AND state IN ('queued','running','blocked')"
            rows = db.execute("SELECT * FROM tasks WHERE project=?" + marks +
                              " ORDER BY created DESC LIMIT 100", (proj,)).fetchall()
            return [self._view(db, r) for r in rows]
        return self._run(client_id, "list", body)

    def summary(self, client_id, project):
        def body(db):
            proj = _name(project)
            me = self._me(db, client_id, proj)
            self._rate(db, me)
            self._light(db, client_id, "read")
            self._recover(db)
            names = {r["client_id"]: r["name"] for r in db.execute("SELECT client_id,name FROM assistants")}
            counts, workers = {}, {}
            for r in db.execute("SELECT assignee,state,COUNT(*) n FROM tasks WHERE project=? GROUP BY assignee,state",
                                (proj,)):
                counts[r["state"]] = counts.get(r["state"], 0) + r["n"]
                workers.setdefault(names.get(r["assignee"]), {})[r["state"]] = r["n"]
            return {"project": proj, "totals": counts, "by_assistant": workers, "grants_no_permissions": True}
        return self._run(client_id, "summary", body)


# -- MCP tools ---------------------------------------------------------------------------------
PROPOSE_SCOPE, REVIEW_SCOPE = "workspace.propose", "workspace.review"
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
BOARD_WRITE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}
TOOLS = ("commander_task_create", "commander_task_claim", "commander_task_progress", "commander_task_finish",
         "commander_task_withdraw", "commander_task_list", "commander_task_summary",
         "commander_task_instruct", "commander_task_ack")


def _error(code, detail=None):
    value = {"ok": False, "error": code}
    if detail is not None:
        value["detail"] = detail
    return value


def register(server, board, *, get_access_token, required_scope=PROPOSE_SCOPE):
    """Attach the task-board tools. Identity is the verified OAuth client id of the calling token."""
    if not isinstance(board, Board) or not callable(get_access_token):
        raise ValueError("Task board and verified token source required")

    def who():
        token = get_access_token()
        client = getattr(token, "client_id", None)
        if token is None or type(client) is not str or not CLIENT.fullmatch(client):
            return None, _error("not_authorized")
        scopes = set(getattr(token, "scopes", ()) or ())
        if REVIEW_SCOPE in scopes:
            return None, _error("assistant_session_must_not_have_review_scope")
        if required_scope not in scopes:
            return None, _error("not_authorized")
        return client, None

    def call(fn, *args, **kwargs):
        client, error = who()
        if error:
            return error
        try:
            return {"ok": True, "result": fn(client, *args, **kwargs)}
        except Denied as denied:
            return _error(denied.code, denied.detail)
        except Exception:
            return _error("request_refused")

    def create(project: str, title: str, description: str = "", assignee_client_id: str = "",
               claims: list[str] | None = None, priority: int = 3, ref: str = "", kind: str = "work",
               parent_task_id: str = "") -> dict:
        return call(board.create, project, title, description=description, assignee=assignee_client_id or None,
                    claims=claims or [], priority=priority, ref=ref or None, kind=kind,
                    parent_task_id=parent_task_id or None)

    def claim() -> dict:
        return call(board.claim)

    def progress(task_id: str, lease_id: str, percent: int, note: str = "") -> dict:
        return call(board.progress, task_id, lease_id, percent, note)

    def finish(task_id: str, lease_id: str, outcome: str, summary: str = "", verdict: str = "") -> dict:
        return call(board.finish, task_id, lease_id, outcome, summary, verdict=verdict or None)

    def withdraw(task_id: str) -> dict:
        return call(board.withdraw, task_id)

    def instruct(task_id: str, text: str) -> dict:
        return call(board.instruct, task_id, text)

    def ack(task_id: str, lease_id: str, instruction_id: str) -> dict:
        return call(board.ack, task_id, lease_id, instruction_id)

    def listing(project: str, include_finished: bool = False) -> dict:
        return call(board.list_tasks, project, include_finished=include_finished)

    def summary(project: str) -> dict:
        return call(board.summary, project)

    note = " This only updates the shared task board; it grants no permission and runs nothing."
    for name, title, text, fn, ann in (
            ("commander_task_instruct", "Queue an instruction for a task",
             "Queue a follow-up for a task. It is delivered at the assignee's next checkpoint and never "
             "interrupts current work." + note, instruct, BOARD_WRITE),
            ("commander_task_ack", "Acknowledge a delivered instruction",
             "Acknowledge an instruction you received for the task you hold." + note, ack, BOARD_WRITE),
            ("commander_task_create", "Add a task to the shared board",
             "Add a work task, or a review task (kind='review' with parent_task_id) for a different assistant "
             "to check another task. Claims (path:, branch:, mr:, pr:, issue:) must not overlap active work."
             + note, create, BOARD_WRITE),
            ("commander_task_claim", "Take your next assigned task",
             "Claim your highest-priority queued task and receive a lease id." + note, claim, BOARD_WRITE),
            ("commander_task_progress", "Report progress on your task",
             "Report progress and extend your lease. 'lease_lost' means the task was cancelled or "
             "reassigned: stop work." + note, progress, BOARD_WRITE),
            ("commander_task_finish", "Report your task as done or failed",
             "Finish the task you hold the lease for. Reviews finishing as done need a verdict: "
             "approve, approve-with-changes or object." + note, finish, BOARD_WRITE),
            ("commander_task_withdraw", "Withdraw a task from the board",
             "Cancel a task you created or hold. The worker stops at its next checkpoint." + note,
             withdraw, BOARD_WRITE),
            ("commander_task_list", "List tasks in a project", "Read-only. Titles and states only.", listing, READ_ONLY),
            ("commander_task_summary", "Summarize a project's task board", "Read-only counts per assistant.",
             summary, READ_ONLY)):
        server.tool(name=name, title=title, description=text, annotations=ann)(fn)
    return board
