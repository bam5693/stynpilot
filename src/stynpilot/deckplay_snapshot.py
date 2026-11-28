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
POLICY = "deckplay-clean-snapshot-v4"
REF = "refs/heads/stynpilot-import"

# Filename entropy false positives from the reviewed DeckPlay source tree.
# Each pair pins the UTF-8 path and raw blob. Content still passes the scanner.
_REVIEWED_TREE = "aaec79d0f851d6c4d3d6f7612b19b51216fa2c11"
_MIGRATION_PATH = re.compile(r"supabase/migrations/[0-9]{14}_[a-z0-9_]+\.sql")
_REPORT_PATH = re.compile(r"tests/reports/[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z0-9-]+\.md")
_LOCAL_TEST_WORKFLOW = ".github/workflows/t2-unread-local.yml"
_LOCAL_TEST_WORKFLOW_BLOB = "c34011831863c49c391f8e59f66316e70c1546030dc10d6c5cf4e18b0d9174cd"
_WORKFLOW_PATH = re.compile(r"\.github/workflows/[a-z0-9-]+\.yml")
# The flagged strings in these specific blobs are existing tracked source paths
# in the workflows' push path lists. Values pin the raw file and finding count.
_WORKFLOW_REFERENCES = {
    "994a20129d373fd90d5205626e9d201728fab95b1794bcc4cfa2a2e5e58be68f":
        ("20946c990b0298451e970605ec8c07fd033d823ad8c572dda7ad917a01b7ce03", 1),
    "2184183b16c95a77cbd7e64a5c40f5b6affe580e2d544b3e1e1ef20535dcb1c7":
        ("ba3874e1c68905479d414f577bc5c26cd41e03b1027d3136940f3c072f0c6438", 1),
    "89a2c6186f95abf0231c16d8c449062abdace60e07335b4d5eb53bf9948ad58e":
        ("89806c1c38992e2601359fa63511397c1a96598afe444b7c63e0108b7c886d56", 1),
    "74d01bde413686e36c6370b8244c2b0ec0cdaf7801cab1d6ee16ed6a0cda9805":
        ("afca7667abddf8c7658344ab9e8439891177349eb6d6f25cb7c95d45df6fa924", 1),
    "fb366a4c7ad9f0572d8b1f86dea57ae658e1f57a15a2c086cd21b32ad8861da4":
        ("a5e503193f25daaf76c6684fac1f75d2c10727705b0cf1341adcc061a903fc90", 2),
    "7e5a0041f657636cd8857b0c6e33edb41a3cf5dc5a3a1000de60943ac3750414":
        ("4a705526c8b9f77348fef7094269fd92bb1825123dcf22a89717f7fe0166cdeb", 1),
    "160875fae657c4ad4a1a44c5dc86911b77d55cf7f855bdc4afb3d5f168b904e5":
        ("0270a0fbb575216ce04bb1d88303874f6cb9ef5982236c765e8ceacf244e27b4", 1),
    "b02ad121d8c87a5c5ffae696a58cd8cf84268c6680716f652cac1979de017720":
        ("8b3b7766252315aa6a85dcf5db3413acf951f72d42679fec2376f950c356a614", 2),
    "084d7d1d42b2eb61e48f3c8e60f2eb939815ac25142d3653118d9958f752b418":
        ("6e2ecb683786fadae6ef42009b4f20f103e52056ead67e32b4d52f6d76ad64ef", 1),
    "1226da272ac04eb1a059d390671bd611f24916b6c41afd8859daf98d3c474814":
        ("a8a482516e82732c105c5c9c0dfa9b76a372b70fc181895c8fb0965bac29adaa", 1),
    "1f4a24f5a1f1547d0f6ae980ba59832c59481af6de6143e2677a1153125a3c55":
        ("0cf0d0663564437959ca63acef0baad71396a7ae84aca81c0a26af7d4a7241b5", 1),
}
# The handoff report references another tracked Markdown file by name.
_REPORT_REFERENCES = {
    "9357c2eb7127884f672e6660836e38100a1661073884126613eecb06bbe4f2f2":
        ("a4ad65fa90ba7212627215563bf35a72fd7dab3aae19243d2a2e36c9212deb94", 1),
}
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
_REPORT_BLOBS = {
    "08b0896159546d266f10be70515f9730ef540db35e9345d0539502c27d46e5ac":
        "7cad6f0ad6f73201459af0a34a61cf54c7dd314930d75e26ed92cdb9407ee3cb",
    "3ef36e3ef31734c1ee6943145f2cdb69e45f701f9e2726bf301c7b18cb9571d5":
        "5c33116eea78d475c9514ee1aabb50f4ed54ba756cf7ee57b4567328d27b3349",
    "437dc3121d5f6d7bcbcd8688ce04feb4bf6879f0d4fb0595deb3a47f5bce6820":
        "512ed1a3d07d52f75df266fac7c935989e108ba1c6ebd634e3282c5497cf56d7",
    "a8c75fa1c09624283dbf1608bbe43bc9dc343d43fefb740e9a46e670e75a37de":
        "2aa62443d037d1c9f697e294faa6aa31bf4dc3b99f04f32c17e3acd9552e1337",
    "9d46054cd1d6b7662d0ab9fb2de202d6b7f95f1aea755c2130ca2f20be0f535c":
        "b4a55fe865451fa194539ee6b1775bd29e8bf0b20d8f5eb9e5c1151785f8d8ae",
}


def path_admitted(tree, path, data):
    if not archive_store._unprotected_path(path):
        return False
    flags = redact.redact(path)[1]
    if not flags:
        return True
    if tree != _REVIEWED_TREE or set(flags) != {"random-string"}:
        return False
    if path == _LOCAL_TEST_WORKFLOW:
        return hashlib.sha256(data).hexdigest() == _LOCAL_TEST_WORKFLOW_BLOB
    if _reviewed_reference(tree, path, data) is not None:
        return True
    if _MIGRATION_PATH.fullmatch(path):
        reviewed = _MIGRATION_BLOBS
    elif _REPORT_PATH.fullmatch(path):
        reviewed = _REPORT_BLOBS
    else:
        return False
    return reviewed.get(hashlib.sha256(path.encode("utf-8")).hexdigest()) == hashlib.sha256(data).hexdigest()


def _reviewed_reference(tree, path, data):
    if tree != _REVIEWED_TREE:
        return None
    if _WORKFLOW_PATH.fullmatch(path):
        pins = _WORKFLOW_REFERENCES
    elif _REPORT_PATH.fullmatch(path):
        pins = _REPORT_REFERENCES
    else:
        return None
    reviewed = pins.get(hashlib.sha256(path.encode("utf-8")).hexdigest())
    if reviewed is not None and reviewed[0] == hashlib.sha256(data).hexdigest():
        return reviewed[1]
    return None


def content_refusal(data, *, tree="", path=""):
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    if "\0" in decoded:
        return "binary"
    findings = redact.redact(decoded)[1]
    if findings and findings != {"random-string": _reviewed_reference(tree, path, data)}:
        return "sensitive"
    return None


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise git.ArchiveError("snapshot_review_timeout")
    return min(8, remaining)


def _call(bare, deadline, *args):
    return git._git(bare, *args, timeout=_remaining(deadline))


def _review(bare, commit, deadline, target=None, *, admitted_tree=None):
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
        if not path_admitted(admitted_tree or source_tree, path, data):
            blocked["protected"] += 1
            continue
        refusal = content_refusal(data, tree=admitted_tree or source_tree, path=path)
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



@contextmanager
def stage_publication(store, client, source_plan, source_plan_sha256, snapshot_commit,
                      work_bundle, work_bundle_sha256, work_ref, work_commit, work_tree, *, expected_remote):
    """Attach an exact reviewed snapshot tree to its original ancestry offline.

    The caller must supply trusted checkout provenance and an exact reviewed
    work bundle. The yielded repository is owner-private and cannot be exported
    back into the development workspace. This stage does not push a branch.
    """
    validate_plan(source_plan, source_plan_sha256)
    if (any(type(value) is not str or not git.OID.fullmatch(value)
            for value in (snapshot_commit, work_commit, work_tree, expected_remote))
            or type(work_bundle_sha256) is not str or not git.DIGEST.fullmatch(work_bundle_sha256)
            or type(work_ref) is not str or not work_ref.startswith(("refs/heads/work/", "refs/heads/test/"))
            or not git._ref_name(work_ref)):
        raise git.ArchiveError("snapshot_publication_invalid")
    deadline = time.monotonic() + MAX_SECONDS
    original = source_plan["source_commit"]
    with store._deckplay_transfer_bundle(client, source_plan["archive_id"], source_plan["ref"], original) as (base, receipt):
        if receipt["source_bundle_sha256"] != source_plan["source_bundle_sha256"]:
            raise git.ArchiveError("snapshot_origin_changed")
        with tempfile.TemporaryDirectory(prefix="stynpilot-deckplay-publication-") as private:
            private = Path(private)
            incoming = private / "work.bundle"
            work = private / "work.git"
            publication = private / "publication.git"
            with incoming.open("xb") as frozen:
                if git._bundle_digest(work_bundle, copy_to=frozen)[0] != work_bundle_sha256:
                    raise git.ArchiveError("archive_bundle_digest_mismatch")
            git._restore_bundle(incoming, work, {work_ref: work_commit}, work_ref)
            if (_call(work, deadline, "rev-list", "--max-parents=0", work_commit).splitlines() != [snapshot_commit.encode()]
                    or _call(work, deadline, "rev-parse", snapshot_commit + "^{tree}").strip()
                    != source_plan["source_tree"].encode()):
                raise git.ArchiveError("snapshot_work_history_mismatch")
            git._restore_bundle(base, publication, {source_plan["ref"]: original}, source_plan["ref"])
            if _call(publication, deadline, "rev-parse", original + "^{tree}").strip() != source_plan["source_tree"].encode():
                raise git.ArchiveError("snapshot_origin_changed")
            review = _review(work, work_commit, deadline, target=(private / "blob", publication),
                             admitted_tree=source_plan["source_tree"])
            tree = _call(publication, deadline, "write-tree").decode("ascii").strip()
            if not review["eligible"] or review["source_tree"] != work_tree or tree != work_tree:
                raise git.ArchiveError("snapshot_publication_review_required")
            commit = _call(publication, deadline, "-c", "user.name=StyNpilot reviewed snapshot",
                           "-c", "user.email=snapshot@stynpilot.invalid", "commit-tree", tree,
                           "-p", original, "-m", "Apply reviewed DeckPlay work " + work_commit).decode("ascii").strip()
            if not git.OID.fullmatch(commit):
                raise git.ArchiveError("snapshot_commit_invalid")
            _call(publication, deadline, "update-ref", work_ref, commit)
            _call(publication, deadline, "fsck", "--full", "--strict", "--no-dangling")
            if expected_remote != "0" * 40:
                try:
                    _call(publication, deadline, "merge-base", "--is-ancestor", expected_remote, commit)
                except git.ArchiveError:
                    raise git.ArchiveError("snapshot_destination_not_ancestor") from None
            yield publication, {"commit": commit, "tree": tree, "parent": original, "work_commit": work_commit,
                                "ref": work_ref, "origin": source_plan["source"]["url"], "expected_remote": expected_remote}
