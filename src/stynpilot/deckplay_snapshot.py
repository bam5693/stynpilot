"""Stage a reviewed DeckPlay working snapshot without copying archived history.

Only an owner-side caller may consume the private artifact. This module has no
MCP route, network, owner-proof authority or workspace mutation. A future
approval-bound consumer must verify the exact plan and target before import.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import tempfile
import time

from . import archive_store, redact, repo_archive as git

MAX_ENTRIES = 2048
MAX_TOTAL = 64 << 20
MAX_BLOB = 4 << 20
MAX_SECONDS = 60
POLICY = "deckplay-clean-snapshot-v1"
REF = "refs/heads/stynpilot-import"


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise git.ArchiveError("snapshot_review_timeout")
    return min(8, remaining)


def _call(bare, deadline, *args):
    return git._git(bare, *args, timeout=_remaining(deadline))


def _review(bare, commit, deadline, target=None):
    tree = archive_store._tree(bare, commit)
    if not 0 < len(tree) <= MAX_ENTRIES:
        raise git.ArchiveError("snapshot_entry_limit")
    source_tree = _call(bare, deadline, "rev-parse", commit + "^{tree}").decode("ascii").strip()
    blocked = {"protected": 0, "nonregular": 0, "oversize": 0, "binary": 0, "sensitive": 0}
    total = 0
    for path, row in sorted(tree.items()):
        if not archive_store._safe_path(path):
            blocked["protected"] += 1
            continue
        if row["mode"] not in ("100644", "100755") or row["type"] != "blob":
            blocked["nonregular"] += 1
            continue
        oid = row["object"]
        size = int(_call(bare, deadline, "cat-file", "-s", oid))
        total += size
        if total > MAX_TOTAL:
            raise git.ArchiveError("snapshot_byte_limit")
        if size > MAX_BLOB:
            blocked["oversize"] += 1
            continue
        data = _call(bare, deadline, "cat-file", "blob", oid)
        if len(data) != size or hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + data).hexdigest() != oid:
            raise git.ArchiveError("snapshot_object_changed")
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            blocked["binary"] += 1
            continue
        if "\0" in decoded:
            blocked["binary"] += 1
            continue
        if redact.redact(decoded)[1]:
            blocked["sensitive"] += 1
            continue
        if target is not None:
            # Copy raw bytes, not checkout filters or export-ignore attributes.
            scratch, new_repo = target
            scratch.write_bytes(data)
            actual = _call(new_repo, deadline, "hash-object", "-w", "--no-filters", str(scratch)).decode("ascii").strip()
            if actual != oid:
                raise git.ArchiveError("snapshot_object_changed")
            _call(new_repo, deadline, "update-index", "--add", "--cacheinfo", row["mode"] + "," + oid + "," + path)
    return {"policy": POLICY, "source_tree": source_tree, "entry_count": len(tree),
            "scanned_bytes": total, "blocked": blocked, "eligible": not any(blocked.values())}


def _plan(store, client, archive_id, ref, commit, deadline, target=None):
    bare, receipt = store._deckplay_checkout_binding(client, archive_id, ref, commit)
    review = _review(bare, commit, deadline, target=target)
    return {"archive_id": archive_id, "source": dict(receipt["source"]),
            "source_bundle_sha256": receipt["bundle_sha256"], "ref": ref,
            "source_commit": commit, "workspace": "deckplay-hq", **review}


def review(store, client, archive_id, ref, commit):
    """Return metadata only. Heuristic scans are not a proof of secret absence."""
    with store._locked():
        return _plan(store, client, archive_id, ref, commit, time.monotonic() + MAX_SECONDS)


def plan_digest(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_plan(plan, digest):
    fields = {"archive_id", "source", "source_bundle_sha256", "ref", "source_commit", "workspace",
              "policy", "source_tree", "entry_count", "scanned_bytes", "blocked", "eligible"}
    if (type(plan) is not dict or set(plan) != fields or plan["source"] != archive_store._DECKPLAY_SOURCE
            or plan["workspace"] != "deckplay-hq" or plan["policy"] != POLICY
            or type(plan["archive_id"]) is not str or not archive_store._ARCHIVE.fullmatch(plan["archive_id"])
            or type(plan["ref"]) is not str or not plan["ref"].startswith("refs/heads/") or not git._ref_name(plan["ref"])
            or any(type(plan[key]) is not str or not git.OID.fullmatch(plan[key]) for key in ("source_commit", "source_tree"))
            or type(plan["source_bundle_sha256"]) is not str or not git.DIGEST.fullmatch(plan["source_bundle_sha256"])
            or type(plan["entry_count"]) is not int or not 0 < plan["entry_count"] <= MAX_ENTRIES
            or type(plan["scanned_bytes"]) is not int or not 0 <= plan["scanned_bytes"] <= MAX_TOTAL
            or type(plan["blocked"]) is not dict
            or set(plan["blocked"]) != {"protected", "nonregular", "oversize", "binary", "sensitive"}
            or any(type(value) is not int or value != 0 for value in plan["blocked"].values())
            or plan["eligible"] is not True or type(digest) is not str or plan_digest(plan) != digest):
        raise git.ArchiveError("snapshot_approval_plan_invalid")


@contextmanager
def stage(store, client, archive_id, ref, commit, expected_plan_sha256):
    """Build a single-root snapshot; refuse incomplete or changed reviews.

    Never export the original object database. Exact original ancestry stays
    in the owner-private archive. This is staging only, not owner approval.
    """
    with store._locked():
        deadline = time.monotonic() + MAX_SECONDS
        with tempfile.TemporaryDirectory(prefix="stynpilot-deckplay-snapshot-") as folder:
            folder = Path(folder)
            fresh = folder / "snapshot.git"
            _call(None, deadline, "init", "--bare", "--quiet", "--template=", str(fresh))
            plan = _plan(store, client, archive_id, ref, commit, deadline,
                         target=(folder / "blob", fresh))
            if plan_digest(plan) != expected_plan_sha256:
                raise git.ArchiveError("snapshot_plan_changed")
            if not plan["eligible"]:
                raise git.ArchiveError("snapshot_review_required")
            tree = _call(fresh, deadline, "write-tree").decode("ascii").strip()
            if tree != plan["source_tree"]:
                raise git.ArchiveError("snapshot_tree_changed")
            snapshot = _call(fresh, deadline, "-c", "user.name=StyNpilot snapshot",
                             "-c", "user.email=snapshot@stynpilot.invalid", "commit-tree", tree,
                             "-m", "DeckPlay source snapshot " + commit).decode("ascii").strip()
            if not git.OID.fullmatch(snapshot):
                raise git.ArchiveError("snapshot_commit_invalid")
            _call(fresh, deadline, "update-ref", REF, snapshot)
            bundle = folder / "snapshot.bundle"
            _call(fresh, deadline, "bundle", "create", str(bundle), REF)
            digest, size = git._bundle_digest(bundle)
            git._verify_bundle(bundle, {REF: snapshot})
            yield bundle, {**plan, "plan_sha256": expected_plan_sha256, "snapshot_commit": snapshot,
                           "snapshot_bundle_sha256": digest, "snapshot_bundle_size": size}
