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
import re
import tempfile
import time

from . import archive_store, redact, repo_archive as git

MAX_ENTRIES = 2048
MAX_TOTAL = 64 << 20
MAX_BLOB = 4 << 20
MAX_SECONDS = 60
POLICY = "deckplay-clean-snapshot-v2"
REF = "refs/heads/stynpilot-import"

# Filename entropy false positives from the reviewed DeckPlay source tree.
# Each pair pins the UTF-8 path and raw blob. Content still passes the scanner.
_MIGRATION_TREE = "aaec79d0f851d6c4d3d6f7612b19b51216fa2c11"
_MIGRATION_PATH = re.compile(r"supabase/migrations/[0-9]{14}_[a-z0-9_]+\.sql")
_MIGRATION_BLOBS = {
    "f92c89f31e4a8bf48adf8c9956d0794dfe0ffac1f5ea61d166748b8a6b83e93b":
        "dd9820c891621132252561cb8c87a62574861c60b72eb41d0c57ed46f18cc3f3",
    "8bf9f425f0e76f465ce3258721d5cf0e1c68b8087b74847cc4f4415af7d3e7d5":
        "2b55add6ba4221db4681003f2181ea96c2331838af345ffb0237b84b2e9e5e6c",
    "8d72295f9b9fa8c4b8ce64ead760737b0628ca44449cbc057f3bc8d8b91adbcc":
        "0908cdba2b900e691625fc718fb05afe2551e5762a94b54eff9451a64578b14c",
    "20130d2faa598b26c16a338f4015e7d7edf810bc86e5b8c81c836266e4c55ba2":
        "3834658a1d98605b638a801508dd02db04ad8a3cb78edf0d97338c11c8d1397a",
    "31a3a2ec1004fe809c8668b3dffece2b9f303d554293270d8dbc3553be0fa154":
        "b221f85ffd2b85b8bf92ce9938e2de0d3dbc63a6ca3f19b6666f5433f8eb70c4",
    "8345791c46a028de1f688d3b09882d7b5d266af45149f2a8851449b8ee19ec7a":
        "141c129cf5115b6b0cccbe857258e484c370d28fb7175cb4d16f995b1a161f33",
    "a388acd2ab45656ea49b7fdca6a4d95924caaf7bbce457a5f64bc77749325475":
        "e4fa3c5d5fc359fa07ca60747b950e8fb2ec0945f928775b2c0f5cb8959995c3",
    "af82c0b2450780a4a3857bff9624f78c3f6f48cb98df13b9d582cdc525a35b8d":
        "3f066b0472d876a2aa6daec20f6eca9c52aa2e6cbbadfc22b2fd5c82aba67dfb",
    "0b923b11db86e5f393acda69e6232796ccd6d0cd63578244c6defec09ed75896":
        "b2c16e2f0fcd1eb1fd495d30540eaeff4691c84c2c7f9312ccc5ac0863242666",
    "19c5ac30ad9b079c3baa605a09b350002df9c95da419ce99223493525b2d7631":
        "9f6c8aec0cac3165d4ca0cb373883d2152452c3391700116efb65eff70eca212",
    "d271345efb5e096685f99be6026838494f1ecc6af3c1509319a225462b2a78a2":
        "aebd8820dbd2ae109ab8c6ad3344739eb60371fe6f20cc2b3cfa75268a7363a3",
    "763b6e6bf385ac634e75d231e02788e74ca66f34748ffe16edb1552ef7f2b4bc":
        "7b4b0bfc5e92a8bb070788bafeee0b7f43e5b866b60733b783ba0b618bf0f78e",
}


def path_admitted(tree, path, data):
    if not archive_store._unprotected_path(path):
        return False
    flags = redact.redact(path)[1]
    if not flags:
        return True
    return (tree == _MIGRATION_TREE and set(flags) == {"random-string"}
            and _MIGRATION_PATH.fullmatch(path) is not None
            and _MIGRATION_BLOBS.get(hashlib.sha256(path.encode("utf-8")).hexdigest())
            == hashlib.sha256(data).hexdigest())


def content_refusal(data):
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    if "\0" in decoded:
        return "binary"
    return "sensitive" if redact.redact(decoded)[1] else None


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
        if not archive_store._unprotected_path(path):
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
        if not path_admitted(source_tree, path, data):
            blocked["protected"] += 1
            continue
        refusal = content_refusal(data)
        if refusal:
            blocked[refusal] += 1
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
