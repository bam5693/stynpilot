"""dev16: the release authority. Build from an exact commit (twice, identical, tests green), then ONE owner approval signs,
publishes to GitHub and starts the protected upgrade. Fakes stand in for git/pytest and for GitHub; the installer, approval check,
upgrade preparation and manifest signature checks are the real ones."""
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
try:
    import test_dev4_upgrade as tu
    from stynpilot import release, release_console
    from stynpilot.broker.executor import ExecutionDenied
    from stynpilot.broker.release_authority import Authority, AuthorityError, default_http
    from stynpilot.requests import request_id
    from stynpilot.broker.proof import render_summary
except ImportError:          # pragma: no cover
    tu = None

COMMIT = "c" * 40
RID = "9" * 64
VERSION = "0.1.0~dev4"


class FakeMachine:
    """Pretends to be git + the build + pytest inside the builder's work folder, and records every step that ran."""
    LOCK = "# vendored\nmcp==1.30.0 " + "a" * 64 + "\n"
    LAB_SOURCE = b"before candidate code"

    def __init__(self, deb_bytes, *, tests="1 passed in 1.0s", tests_code=0, second_build=None, commit=None, version="0.1.0.dev4",
                 pip_code=0):
        self.deb, self.tests, self.tests_code, self.second = deb_bytes, tests, tests_code, second_build
        self.commit, self.version, self.pip_code = commit, version, pip_code
        self.calls, self.fetched, self.stopped, self.mounts, self.unit_state = [], None, [], [], "inactive"

    def __call__(self, argv, timeout, cwd=None, env=None):
        if argv[:3] == ["/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--"]:           # host mount namespace
            self.host_calls = getattr(self, "host_calls", 0) + 1
            argv = [argv[3].rsplit("/", 1)[-1]] + argv[4:]
        if argv[0] in ("systemctl", "mount", "umount"):
            (self.stopped if argv[0] == "systemctl" else self.mounts).append(argv)
            if argv[0] == "mount" and getattr(self, "mountinfo", None):
                with open(self.mountinfo, "a") as handle:
                    handle.write("99 1 0:99 / %s rw - %s tmpfs rw\n" % (argv[-1], getattr(self, "fstype", "tmpfs")))
            return 0, (self.unit_state if "is-active" in argv else "")
        assert argv[0] == "env", argv                  # always run through the unprivileged-account prefix
        args, work = list(argv[1:]), cwd
        if args and args[0].startswith("WORKSPACE="):
            work, args = args[0].split("=", 1)[1], args[1:]
        work = Path(work)
        self.calls.append(args)
        if args[0] == "/usr/bin/git":
            if "init" in args:
                (work / "src").mkdir()
            elif "fetch" in args:
                self.fetched = args[-1]
            elif "rev-parse" in args:
                return 0, "...\n" + (self.commit or self.fetched) + "\n"
            elif "bundle" in args:
                (work / "checkout.bundle").write_bytes(b"fixture git bundle")
            elif "archive" in args:
                (work / "lab-source.tar").write_bytes(self.LAB_SOURCE)
            return 0, ""
        if args[:3] == ["/usr/bin/python3", "-I", "-c"]:
            return 0, self.version + "\n"
        if args[0] == "/usr/bin/cat" and args[1].startswith(".shared-"):
            if getattr(self, "private_namespace", False):                   # the Dev19 bug: the sandbox sees a different folder
                return 1, "cat: No such file or directory"
            return 0, (work / args[1]).read_text()
        if args[0] == "/usr/bin/cat":
            return 0, self.LOCK
        if args[:4] == ["/usr/bin/python3", "-m", "pip", "download"]:
            return self.pip_code, ""
        script = args[-1]
        m = re.search(r"build_deb\.build\('\.\./out(\d)'", script)
        if m:
            out = work / ("out" + m.group(1))
            out.mkdir()
            data = self.deb if m.group(1) == "0" or self.second is None else self.second
            (out / "stynpilot_x_all.deb").write_bytes(data)
            if (work / "lab-source.tar").exists():
                (work / "lab-source.tar").write_bytes(b"changed by executing candidate")
            return 0, ""
        if "pytest" in script:
            return self.tests_code, "....\n" + self.tests + "\n"
        return 1, "unexpected command"


class FakeGitHub:
    """A small GitHub: draft releases, assets served through a redirect, real tag creation when a release goes public."""
    def __init__(self):
        self.calls, self.releases, self.blobs, self.tags = [], {}, {}, {}
        self.next_id, self.fail_upload, self.token_status = 100, False, 200
        self.tag_override, self.serve_override, self.annotated = None, {}, set()

    def tag_url(self, tag):
        return "https://api.github.com/repos/bam5693/stynpilot/git/ref/tags/" + tag

    def __call__(self, method, url, headers, body, max_bytes=0):
        self.calls.append((method, url, headers, body))
        assert headers["Authorization"].startswith("Bearer ")
        base = "https://api.github.com/repos/bam5693/stynpilot"
        j = lambda obj, code=200: (code, json.dumps(obj).encode())
        if url == base:
            return (200, json.dumps({"permissions": {"push": True}}).encode()) if self.token_status == 200 else (self.token_status, b"{}")
        m = re.fullmatch(re.escape(base) + r"/git/ref/tags/(.+)", url)
        if m:
            sha = self.tags.get(m.group(1))
            if sha is None:
                return 404, b"{}"
            if m.group(1) in self.annotated:
                return j({"object": {"type": "tag", "sha": "t" * 40}})
            return j({"object": {"type": "commit", "sha": sha}})
        if url == base + "/git/tags/" + "t" * 40:
            tag = next(iter(self.annotated))
            return j({"object": {"type": "commit", "sha": self.tags[tag]}})
        if url == base + "/releases?per_page=100":
            return j(list(self.releases.values()))
        if url == base + "/releases" and method == "POST":
            data = json.loads(body)
            self.next_id += 1
            rel = {"id": self.next_id, "tag_name": data["tag_name"], "target_commitish": data["target_commitish"],
                   "draft": data["draft"], "prerelease": data["prerelease"], "body": data["body"], "name": data["name"], "assets": []}
            self.releases[self.next_id] = rel
            return j(rel, 201)
        m = re.fullmatch(re.escape(base) + r"/releases/(\d+)", url)
        if m:
            rel = self.releases[int(m.group(1))]
            if method == "PATCH":
                rel["draft"] = json.loads(body)["draft"]
                if not rel["draft"]:
                    self.tags[rel["tag_name"]] = self.tag_override or rel["target_commitish"]
            return j(rel)
        m = re.fullmatch(r"https://uploads\.github\.com/repos/[^/]+/[^/]+/releases/(\d+)/assets\?name=(.+)", url)
        if m:
            if self.fail_upload:
                return 500, b"{}"
            self.next_id += 1
            self.blobs[self.next_id] = body
            self.releases[int(m.group(1))]["assets"].append({"id": self.next_id, "name": m.group(2), "size": len(body)})
            return 201, b"{}"
        m = re.fullmatch(re.escape(base) + r"/releases/assets/(\d+)", url)
        if m:
            aid = int(m.group(1))
            if method == "DELETE":
                for rel in self.releases.values():
                    rel["assets"] = [a for a in rel["assets"] if a["id"] != aid]
                return 204, b""
            assert headers["Accept"] == "application/octet-stream"
            return 302, ("https://objects.githubusercontent.com/blob/%d" % aid).encode()
        raise AssertionError((method, url))

    def fetch(self, url, max_bytes):
        aid = int(url.rsplit("/", 1)[1])
        return self.serve_override.get(aid, self.blobs[aid])

    def assets(self):
        return {a["name"]: self.blobs[a["id"]] for rel in self.releases.values() for a in rel["assets"]}


def accept_all(path, version):
    return None


@unittest.skipIf(tu is None, "needs the upgrade test harness")
class AuthorityTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = Path(t.name)
        os.chmod(self.tmp, 0o700)
        self.deb_bytes = b"!<arch>\npretend package contents" * 100
        self.machine = FakeMachine(self.deb_bytes)
        self.http = FakeGitHub()
        self.auth = self.make(self.tmp, self.machine)

    def make(self, folder, machine, **kw):
        auth = Authority(folder, run=machine, http=self.http, build_prefix=["env"], inspect=kw.pop("inspect", accept_all),
                         fetch=self.http.fetch, **kw)
        auth.init_key()
        auth.set_token("github_pat_" + "A" * 30)
        return auth

    def prepared(self):
        return self.auth.prepare(COMMIT, VERSION, "0.1.0~dev3")

    def test_lab_artifact_is_captured_before_execution_and_rehashed_on_use(self):
        self.auth = self.make(self.tmp / "with-lab", self.machine, retain_lab_source=True, build_uid=os.geteuid())
        record = self.prepared()
        self.assertEqual(record["state"], "ready", record)
        digest = record["lab_source_sha256"]
        self.assertEqual(self.auth.lab_artifact(COMMIT, digest), self.machine.LAB_SOURCE)
        with self.assertRaisesRegex(AuthorityError, "lab_source_not_verified"):
            self.auth.lab_artifact(COMMIT, "1" * 64)
        bundle_sha = record["checkout_bundle_sha256"]
        self.assertEqual(self.auth.checkout_bundle(COMMIT, bundle_sha), b"fixture git bundle")
        with self.assertRaisesRegex(AuthorityError, "checkout_bundle_not_verified"):
            self.auth.checkout_bundle(COMMIT, "1" * 64)
        (self.auth._dir(COMMIT) / "checkout.bundle").write_bytes(b"changed")
        with self.assertRaisesRegex(AuthorityError, "checkout_bundle_digest_mismatch"):
            self.auth.checkout_bundle(COMMIT, bundle_sha)

    def test_a_good_build_is_recorded_with_everything_the_owner_will_see(self):
        got = self.prepared()
        self.assertEqual((got["state"], got["reproducible"], got["tests_passed"], got["tests_failed"]), ("ready", True, 1, 0))
        self.assertEqual(got["sha256"], hashlib.sha256(self.deb_bytes).hexdigest())
        intent = self.auth.intent(COMMIT, VERSION, "looked fine")
        self.assertEqual((intent["commit"], intent["size"], intent["key_id"]), (COMMIT, len(self.deb_bytes), self.auth.key_entry()["key_id"]))
        self.assertEqual(self.http.calls, [])                              # building publishes and signs nothing

    def test_every_way_a_build_can_be_wrong_is_a_failed_record_never_a_ready_one(self):
        cases = {"build_is_not_reproducible": FakeMachine(self.deb_bytes, second_build=b"different"),
                 "tests_failed_2_passed_5": FakeMachine(self.deb_bytes, tests="2 failed, 5 passed in 3s", tests_code=1),
                 "test_result_unreadable": FakeMachine(self.deb_bytes, tests="boom", tests_code=1),
                 "could_not_fetch_that_exact_commit": FakeMachine(self.deb_bytes, commit="d" * 40),
                 "source_version_differs_from_requested_version": FakeMachine(self.deb_bytes, version="0.1.0.dev9"),
                 "dependency_download_failed": FakeMachine(self.deb_bytes, pip_code=1)}
        for why, machine in cases.items():
            got = self.make(self.tmp / ("a-" + why[:8]), machine).prepare(COMMIT, VERSION, "x")
            self.assertEqual((got["state"], got["why"]), ("failed", why), why)
            with self.assertRaises(AuthorityError):
                self.make(self.tmp / ("a-" + why[:8]), machine).intent(COMMIT, VERSION)

    def test_a_failing_test_run_cannot_hide_behind_a_green_looking_summary(self):
        """The shell pipeline through tail used to mask pytest's exit status. The status itself must be honoured."""
        machine = FakeMachine(self.deb_bytes, tests="7 passed in 2s", tests_code=1)
        got = self.make(self.tmp / "mask", machine).prepare(COMMIT, VERSION, "x")
        self.assertEqual((got["state"], got["why"]), ("failed", "tests_exit_status_1"))

    def test_the_package_must_pass_the_upgrade_path_checks_before_it_is_ever_offered(self):
        def refuse(path, version):
            raise type("Refused", (Exception,), {"code": "package_has_install_scripts"})()
        got = self.make(self.tmp / "ins", self.machine, inspect=refuse).prepare(COMMIT, VERSION, "x")
        self.assertEqual((got["state"], got["why"]), ("failed", "package_not_acceptable_package_has_install_scripts"))
        none = self.make(self.tmp / "ins2", self.machine, inspect=None)
        none.inspect = None
        self.assertEqual(none.prepare(COMMIT, VERSION, "x")["why"], "package_inspection_not_configured")

    def test_the_builder_cannot_make_root_publish_a_file_from_elsewhere(self):
        class Sneaky(FakeMachine):
            mode = "file"

            def __call__(self, argv, timeout, cwd=None, env=None):
                result = super().__call__(argv, timeout, cwd=cwd, env=env)
                m = re.search(r"build_deb\.build\('\.\./out(\d)'", argv[-1])
                if m and m.group(1) == "0":
                    out, target = Path(cwd) / "out0", Path(cwd).parent / "elsewhere"
                    if self.mode == "file":                   # the package becomes a link to some other file
                        target.write_bytes(self.deb)
                        (out / "stynpilot_x_all.deb").unlink()
                        (out / "stynpilot_x_all.deb").symlink_to(target)
                    elif self.mode == "folder":               # the whole output folder becomes a link elsewhere
                        target.mkdir()
                        (target / "stynpilot_x_all.deb").write_bytes(self.deb)
                        for f in out.iterdir():
                            f.unlink()
                        out.rmdir()
                        out.symlink_to(target)
                    elif self.mode == "two":                  # a second package appears next to it
                        (out / "other.deb").write_bytes(self.deb)
                    elif self.mode == "fifo":                 # a pipe where a file should be
                        (out / "stynpilot_x_all.deb").unlink()
                        os.mkfifo(out / "stynpilot_x_all.deb")
                return result
        expect = {"file": "package_not_where_the_builder_should_have_put_it", "folder": "package_missing",
                  "two": "more_than_one_package_built", "fifo": "package_not_where_the_builder_should_have_put_it"}
        for mode, why in expect.items():
            machine = Sneaky(self.deb_bytes)
            machine.mode = mode
            auth = self.make(self.tmp / ("sn" + mode), machine, work_root=self.tmp / ("root" + mode))
            got = auth.prepare(COMMIT, VERSION, "x")
            self.assertEqual((got["state"], got["why"]), ("failed", why), mode)

    def test_the_size_limit_is_enforced_while_reading(self):
        from stynpilot.broker import release_authority as ra
        old, ra.MAX_ASSET = ra.MAX_ASSET, 1000
        self.addCleanup(setattr, ra, "MAX_ASSET", old)
        self.assertEqual(self.prepared()["why"], "package_not_where_the_builder_should_have_put_it")

    def test_only_one_build_runs_at_a_time_and_only_the_latest_few_are_kept(self):
        lock = self.auth._take_lock()
        with self.assertRaises(AuthorityError) as e:
            self.auth.prepare(COMMIT, VERSION, "x")
        self.assertEqual(e.exception.code, "another_build_is_running")
        os.close(lock)
        times = iter(range(1000, 2000))
        self.auth.clock = lambda: next(times)
        commits = [c * 40 for c in "abcde"]
        for c in commits:
            self.assertEqual(self.auth.prepare(c, VERSION, "x")["state"], "ready")
        kept = sorted(p.name for p in (self.tmp / "release/builds").iterdir())
        self.assertEqual(kept, sorted(commits[-3:]))

    def test_each_step_runs_in_the_sandbox_and_only_fetching_has_network(self):
        seen = []

        def sandbox(job, argv, workspace, *, seconds, memory_mb, tasks, network):
            seen.append((argv, network, seconds, memory_mb, tasks))
            return ["env", "WORKSPACE=" + workspace] + argv
        auth = self.make(self.tmp / "sb", self.machine, sandbox=sandbox, work_root=self.tmp / "sbroot")
        self.assertEqual(auth.prepare(COMMIT, VERSION, "x")["state"], "ready")
        networked = [a[0][:2] if a[0][0] != "/usr/bin/git" else [x for x in a[0] if x in ("fetch",)] for a in seen if a[1]]
        self.assertEqual(sorted(map(str, networked)), sorted(["['fetch']", "['/usr/bin/python3', '-m']"]))
        self.assertTrue(all(0 < s[2] <= 1500 and 0 < s[3] <= 4096 and 0 < s[4] <= 256 for s in seen))
        self.assertGreaterEqual(len(self.machine.stopped), len(seen))         # every unit is stopped afterwards, whatever happened
        git = [a[0] for a in seen if a[0][0] == "/usr/bin/git"]
        self.assertTrue(all("core.hooksPath=/dev/null" in a for a in git[1:]))
        tests = [a for a in seen if "pytest" in a[0][-1]]
        self.assertEqual(len(tests), 1)
        self.assertFalse(tests[0][1])                                          # the test run has no network

    def mounting(self, where, **kw):
        self.machine.mountinfo = str(self.tmp / ("mountinfo-" + where))
        Path(self.machine.mountinfo).write_text("")
        auth = self.make(self.tmp / where, self.machine, mount_work=True, build_uid=os.getuid(), **kw)
        auth.mountinfo = self.machine.mountinfo
        return auth

    def test_the_work_area_is_a_size_limited_memory_file_system_when_enabled(self):
        auth = self.mounting("mt", tmpfs_mb=64)
        auth.prepare(COMMIT, VERSION, "x")
        mount = [m for m in self.machine.mounts if m[0] == "mount"][0]
        self.assertIn("size=64m", mount[4])
        self.assertTrue(any(m[0] == "umount" for m in self.machine.mounts))
        # mounted and released in the HOST mount namespace, not the installer's private one
        self.assertEqual(self.machine.host_calls, len(self.machine.mounts))

    def test_a_work_area_the_sandbox_cannot_see_fails_closed_before_any_build_step(self):
        # Dev19 try #4: the installer's private mount namespace hid its tmpfs from the sandbox units -> package_missing after tests.
        auth = self.mounting("pn")
        self.machine.private_namespace = True
        record = auth.prepare(COMMIT, VERSION, "x")
        self.assertEqual((record["state"], record["why"]), ("failed", "work_area_not_shared_with_the_sandbox"))
        self.assertFalse([c for c in self.machine.calls if c[0] == "/usr/bin/git"])        # nothing was fetched or built
        self.assertTrue(any(m[0] == "umount" for m in self.machine.mounts))

    def test_a_work_area_that_is_not_a_tmpfs_in_roots_view_fails_closed(self):
        auth = self.mounting("nt")
        self.machine.fstype = "ext4"
        record = auth.prepare(COMMIT, VERSION, "x")
        self.assertEqual((record["state"], record["why"]), ("failed", "work_area_not_visible_to_root"))

    def test_unusable_requests_are_refused_up_front(self):
        for commit, version in (("abc", VERSION), (COMMIT.upper(), VERSION), (COMMIT, "bad version")):
            with self.assertRaises(AuthorityError):
                self.auth.prepare_check(commit, version)
        bare = Authority(self.tmp / "bare", run=self.machine, http=self.http, build_prefix=["env"])
        with self.assertRaises(AuthorityError) as e:
            bare.prepare_check(COMMIT, VERSION)
        self.assertEqual(e.exception.code, "release_authority_not_provisioned")
        nobuilder = Authority(self.tmp / "nb", run=self.machine, http=self.http)
        with self.assertRaises(AuthorityError) as e:
            nobuilder.prepare_check(COMMIT, VERSION)
        self.assertEqual(e.exception.code, "builder_not_configured")

    def test_a_verified_package_that_is_altered_afterwards_is_no_longer_offered(self):
        self.prepared()
        deb = next((self.tmp / "release/builds" / COMMIT).glob("*.deb"))
        os.chmod(deb, 0o600)
        deb.write_bytes(b"swapped")
        with self.assertRaises(AuthorityError) as e:
            self.auth.intent(COMMIT, VERSION)
        self.assertEqual(e.exception.code, "verified_package_was_altered")

    def test_secrets_are_private_files_and_the_key_is_created_once(self):
        for name in ("signing-ed25519.pem", "github-token"):
            self.assertEqual(stat.S_IMODE(os.stat(self.tmp / "release" / name).st_mode), 0o600)
        first = self.auth.key_entry()
        self.assertEqual(Authority(self.tmp, run=self.machine, http=self.http, build_prefix=["env"]).init_key(), first)
        for bad in ("", "short", "has space " + "A" * 30, "semi;colon" + "A" * 30, None, 5):
            with self.assertRaises(AuthorityError):
                self.auth.set_token(bad)

    # -- publication ---------------------------------------------------------------------------------------------------------
    def staged(self):
        self.prepared()
        intent = self.auth.intent(COMMIT, VERSION)
        manifest = self.auth.manifest_for(intent, ["note"])
        return manifest, self.auth.sign(manifest), self.auth.package_bytes(COMMIT)

    def publish_all(self):
        manifest, sig, data = self.staged()
        rid = self.auth.draft(manifest, COMMIT, RID)
        self.auth.upload_and_verify(rid, manifest, sig, data, COMMIT, RID)
        self.auth.make_public(rid, manifest, sig, data, COMMIT, RID)
        return manifest, sig, data, rid

    def test_publication_is_a_verified_draft_made_public_at_the_exact_commit(self):
        manifest, sig, data, rid = self.publish_all()
        hosts = {re.match(r"https://([^/]+)/", c[1]).group(1) for c in self.http.calls}
        self.assertEqual(hosts, {"api.github.com", "uploads.github.com"})
        creates = [json.loads(c[3]) for c in self.http.calls if c[0] == "POST" and c[1].endswith("/releases")]
        self.assertEqual([(c["draft"], c["target_commitish"]) for c in creates], [(True, COMMIT)])      # born as a DRAFT
        order = [c[0] for c in self.http.calls if c[0] in ("POST", "PATCH")]
        self.assertEqual(order[-1], "PATCH")                                    # made public only after every upload
        self.assertEqual(self.http.assets(), {manifest["asset"]: data, "release-manifest.json": release.canonical(manifest),
                                              "release-manifest.json.sig": sig.encode()})
        self.assertEqual(self.http.tags[manifest["tag"]], COMMIT)
        release.verify(json.loads(self.http.assets()["release-manifest.json"]), self.http.assets()["release-manifest.json.sig"].decode(),
                       {self.auth.key_entry()["key_id"]: self.auth._private().public_key()})
        # repeating the last step on the already-public identical release succeeds and changes nothing
        before = len(self.http.calls)
        self.auth.make_public(rid, manifest, sig, data, COMMIT, RID)
        self.assertFalse([c for c in self.http.calls[before:] if c[0] in ("POST", "PATCH", "DELETE")])
        with self.assertRaises(AuthorityError) as e:
            self.auth.draft(manifest, COMMIT, RID)                                   # a public release is never reopened
        self.assertEqual(e.exception.code, "release_is_already_public")

    def test_an_existing_tag_for_a_different_commit_is_refused_even_when_annotated(self):
        manifest, sig, data = self.staged()
        for annotated in (False, True):
            self.http.tags[manifest["tag"]] = "e" * 40
            if annotated:
                self.http.annotated.add(manifest["tag"])
            with self.assertRaises(AuthorityError) as e:
                self.auth.draft(manifest, COMMIT, RID)
            self.assertEqual(e.exception.code, "tag_exists_for_a_different_commit")
            self.assertEqual(self.auth.tag_commit(manifest["tag"]), "e" * 40)
        self.assertEqual(self.http.assets(), {})
        self.http.tags[manifest["tag"]] = COMMIT                                # the same commit, annotated: accepted as the same
        self.assertEqual(self.auth.tag_commit(manifest["tag"]), COMMIT)

    def test_a_public_tag_that_ends_up_somewhere_else_is_never_reported_as_published(self):
        manifest, sig, data = self.staged()
        rid = self.auth.draft(manifest, COMMIT, RID)
        self.auth.upload_and_verify(rid, manifest, sig, data, COMMIT, RID)
        self.http.tag_override = "f" * 40
        with self.assertRaises(AuthorityError) as e:
            self.auth.make_public(rid, manifest, sig, data, COMMIT, RID)
        self.assertEqual(e.exception.code, "published_tag_does_not_point_at_the_approved_commit")

    def test_an_asset_with_the_right_name_but_wrong_content_is_replaced_on_the_draft_and_checked_by_content(self):
        manifest, sig, data = self.staged()
        rid = self.auth.draft(manifest, COMMIT, RID)
        self.auth.upload_and_verify(rid, manifest, sig, data, COMMIT, RID)
        aid = next(a["id"] for a in self.http.releases[rid]["assets"] if a["name"] == "release-manifest.json")
        self.http.blobs[aid] = b"x" * len(self.http.blobs[aid])                 # same name, same size, different bytes
        with self.assertRaises(AuthorityError) as e:
            self.auth.verify_assets(rid, manifest, sig, data)
        self.assertTrue(e.exception.code.startswith("asset_content_differs"))
        self.auth.upload_and_verify(rid, manifest, sig, data, COMMIT, RID)                   # repairs it
        self.assertEqual(self.http.assets()["release-manifest.json"], release.canonical(manifest))
        self.assertEqual(len(self.http.releases[rid]["assets"]), 3)

    def test_an_extra_or_missing_asset_stops_publication(self):
        manifest, sig, data = self.staged()
        rid = self.auth.draft(manifest, COMMIT, RID)
        self.auth.upload_and_verify(rid, manifest, sig, data, COMMIT, RID)
        self.http.releases[rid]["assets"].append({"id": 999, "name": "extra.sh", "size": 1})
        self.http.blobs[999] = b"x"
        with self.assertRaises(AuthorityError) as e:
            self.auth.make_public(rid, manifest, sig, data, COMMIT, RID)
        self.assertEqual(e.exception.code, "release_assets_are_not_exactly_the_approved_three")
        self.assertTrue(self.http.releases[rid]["draft"])                      # still a draft: nothing became public

    # -- dev16 re-review: bounded output, verified sandbox stop, pinned artifact, owned drafts, recovery gates -----------------
    def test_runaway_output_is_bounded_while_it_is_read_and_time_is_enforced(self):
        from stynpilot.broker.release_authority import default_run
        code, out = default_run(["sh", "-c", "yes | head -c 60000000"], 60)
        self.assertEqual(code, 0)
        self.assertLessEqual(len(out), 20000)
        import time as _t
        start = _t.monotonic()
        code, _ = default_run(["sh", "-c", "sleep 30 & sleep 30; wait"], 1)
        self.assertEqual(code, 124)
        self.assertLess(_t.monotonic() - start, 10)

    def test_the_real_exit_status_is_kept_when_output_closes_before_the_command_exits(self):
        # EOF on the pipe is not the end of the command: the status it then reports must be the one recorded, not a kill.
        from stynpilot.broker.release_authority import default_run
        code, out = default_run(["sh", "-c", "echo hi; exec >/dev/null 2>&1; sleep 0.5; exit 3"], 30)
        self.assertEqual((code, out.strip()), (3, "hi"))
        import time as _t
        start = _t.monotonic()
        code, _ = default_run(["sh", "-c", "exec >/dev/null 2>&1; sleep 60"], 3)       # silent and slow: still bounded by the deadline
        self.assertLess(_t.monotonic() - start, 15)
        self.assertEqual(code, 124)                                              # reported as a timeout
        code, _ = default_run(["sh", "-c", "exec >/dev/null 2>&1; sleep 35; exit 4"], 60)   # quiet for longer than 30 s: not cut short
        self.assertEqual(code, 4)

    def test_a_sandbox_unit_that_will_not_stop_fails_the_build(self):
        self.machine.unit_state = "active"
        auth = self.make(self.tmp / "stuck", self.machine, sandbox=lambda job, argv, ws, **k: ["env", "WORKSPACE=" + ws] + argv,
                         work_root=self.tmp / "stuckroot")
        got = auth.prepare(COMMIT, VERSION, "x")
        self.assertEqual((got["state"], got["why"]), ("failed", "sandbox_did_not_stop"))

    def test_a_unit_whose_state_is_unknown_empty_or_unreadable_is_never_assumed_stopped(self):
        for state in ("", "unknown\n", "garbage", "deactivating"):
            machine = FakeMachine(self.deb_bytes)
            machine.unit_state = state
            auth = self.make(self.tmp / ("u" + str(abs(hash(state)))), machine,
                             sandbox=lambda job, argv, ws, **k: ["env", "WORKSPACE=" + ws] + argv, work_root=self.tmp / ("r" + str(abs(hash(state)))))
            self.assertEqual(auth.prepare(COMMIT, VERSION, "x")["why"], "sandbox_did_not_stop", state)

        class TimesOut(FakeMachine):
            def __call__(self, argv, timeout, cwd=None, env=None):
                if argv[:2] == ["systemctl", "is-active"]:
                    return 124, ""
                return super().__call__(argv, timeout, cwd=cwd, env=env)
        auth = self.make(self.tmp / "to", TimesOut(self.deb_bytes), sandbox=lambda job, argv, ws, **k: ["env", "WORKSPACE=" + ws] + argv,
                         work_root=self.tmp / "toroot")
        self.assertEqual(auth.prepare(COMMIT, VERSION, "x")["why"], "sandbox_did_not_stop")

    def test_inspection_commands_on_untrusted_packages_are_bounded(self):
        from stynpilot.broker.upgrade import Upgrader
        code, data, over = Upgrader._bounded(["sh", "-c", "yes"], 1000)
        self.assertTrue(over)
        self.assertLessEqual(len(data), 1000)
        code, data, over = Upgrader._bounded(["sh", "-c", "echo hi"], 1000)
        self.assertEqual((code, data, over), (0, b"hi\n", False))
        import time as _t
        start = _t.monotonic()
        code, data, over = Upgrader._bounded(["sleep", "30"], 1000, timeout=1)
        self.assertTrue(over)
        self.assertLess(_t.monotonic() - start, 10)

    def test_a_failed_step_is_reported_with_its_name_exit_code_and_a_clean_output_tail(self):
        class GitBroken(FakeMachine):
            def __call__(self, argv, timeout, cwd=None, env=None):
                if "init" in argv:
                    return 1, "fatal: boom \x1b[31m\x00 end"
                return super().__call__(argv, timeout, cwd=cwd, env=env)
        auth = self.make(self.tmp / "dg", GitBroken(self.deb_bytes))
        got = auth.prepare(COMMIT, VERSION, "x")
        self.assertEqual(got["why"], "could_not_fetch_that_exact_commit")
        self.assertEqual((got["detail"]["phase"], got["detail"]["code"]), ("git0", 1))
        self.assertIn("fatal: boom", got["detail"]["tail"])
        self.assertNotRegex(got["detail"]["tail"], r"[\x00-\x09\x0b-\x1f]")

    def test_the_test_run_gets_the_vendored_packages_and_still_has_no_network(self):
        seen = []

        def sandbox(job, argv, workspace, *, seconds, memory_mb, tasks, network):
            seen.append((argv, network))
            return ["env", "WORKSPACE=" + workspace] + argv
        auth = self.make(self.tmp / "vt", self.machine, sandbox=sandbox, work_root=self.tmp / "vtroot")
        auth.prepare(COMMIT, VERSION, "x")
        argv, network = [a for a in seen if "pytest" in a[0][-1]][0]
        self.assertFalse(network)
        self.assertIn("zipfile -e", argv[-1])
        self.assertIn("PYTHONPATH=src:../vendor", argv[-1])
        self.assertNotIn("pip", argv[-1])

    def test_the_package_is_written_in_process_with_no_tar_or_dpkg_deb_child(self):
        # The live builder's seccomp sandbox made GNU tar (run by dpkg-deb) fail with ENOSYS; the package is now written by Python.
        import os
        import shutil
        import subprocess as sp
        import sys as _sys
        import tempfile
        _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
        import build_deb
        with tempfile.TemporaryDirectory() as d:
            pkg = Path(d) / "pkg"
            (pkg / "DEBIAN").mkdir(parents=True)
            (pkg / "DEBIAN/control").write_text("Package: x\nVersion: 1\nArchitecture: all\nMaintainer: a <a@b>\nDescription: t\n")
            (pkg / "usr/bin").mkdir(parents=True)
            (pkg / "usr/bin/tool").write_text("#!/bin/sh\n")
            (pkg / "usr/bin/tool").chmod(0o700)
            (pkg / "usr/share").mkdir()
            (pkg / "usr/share/odd").write_text("odd length!")
            real, build_deb.subprocess.run = build_deb.subprocess.run, lambda *a, **k: self.fail("a child process was started")
            self.addCleanup(setattr, build_deb.subprocess, "run", real)
            one, two = Path(d) / "one.deb", Path(d) / "two.deb"
            build_deb.write_deb(pkg, one, 1763769600)
            os.utime(pkg / "usr/bin/tool", (5, 5))
            build_deb.write_deb(pkg, two, 1763769600)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            self.assertTrue(one.read_bytes().startswith(b"!<arch>\ndebian-binary   1763769600  0     0     100644  4         `\n2.0\n"))
            if tu is not None and tu.have_dpkg():
                build_deb.subprocess.run = real
                out = sp.run(["dpkg-deb", "-c", str(one)], capture_output=True, text=True, check=True).stdout
                self.assertIn("-rwxr-xr-x root/root", out)
                self.assertIn("./usr/bin/tool", out)
                self.assertEqual(sp.run(["dpkg-deb", "-f", str(one), "Package"], capture_output=True, text=True).stdout.strip(), "x")
            (pkg / "usr/link").symlink_to("bin")
            with self.assertRaises(SystemExit):
                build_deb.write_deb(pkg, Path(d) / "bad.deb", 1763769600)

    def test_readiness_recognises_the_production_sandbox_builder(self):
        sandboxed = Authority(self.tmp / "rd", run=self.machine, http=self.http, sandbox=lambda *a, **k: [])
        self.assertTrue(sandboxed.ready()["builder"])
        self.assertFalse(Authority(self.tmp / "rd2", run=self.machine, http=self.http).ready()["builder"])

    def test_a_work_area_left_mounted_by_a_crashed_build_is_released_first(self):
        auth = self.mounting("sm")
        auth.prepare(COMMIT, VERSION, "x")
        kinds = [m[0] for m in self.machine.mounts]
        self.assertEqual(kinds[0], "umount")                       # before the new mount

    def test_an_unrelated_draft_with_the_same_tag_is_never_adopted_or_touched(self):
        manifest, sig, data = self.staged()
        self.http.next_id += 1
        mine = {"id": self.http.next_id, "tag_name": manifest["tag"], "target_commitish": COMMIT, "draft": True, "prerelease": True,
                "body": "someone else's draft", "name": manifest["tag"], "assets": []}
        self.http.releases[mine["id"]] = mine
        with self.assertRaises(AuthorityError) as e:
            self.auth.draft(manifest, COMMIT, RID)
        self.assertEqual(e.exception.code, "existing_release_not_owned_by_this_transaction")
        # another transaction's marker, or the right marker on the wrong target, is not ours either
        mine["body"] = self.auth._marker("8" * 64)
        with self.assertRaises(AuthorityError):
            self.auth.draft(manifest, COMMIT, RID)
        mine["body"], mine["target_commitish"] = self.auth._marker(RID), "e" * 40
        with self.assertRaises(AuthorityError):
            self.auth.draft(manifest, COMMIT, RID)
        mine["target_commitish"] = COMMIT
        for call in (lambda: self.auth.upload_and_verify(mine["id"], manifest, sig, data, COMMIT, "8" * 64),
                     lambda: self.auth.make_public(mine["id"], manifest, sig, data, COMMIT, "8" * 64)):
            with self.assertRaises(AuthorityError):
                call()
        self.assertEqual(self.http.assets(), {})
        self.assertFalse([c for c in self.http.calls if c[0] in ("PATCH", "DELETE")])
        self.assertEqual(self.auth.draft(manifest, COMMIT, RID), mine["id"])        # its own draft IS found again (crash recovery)

    def test_the_bytes_are_checked_against_the_approved_hash_right_before_upload(self):
        manifest, sig, data = self.staged()
        rid = self.auth.draft(manifest, COMMIT, RID)
        with self.assertRaises(AuthorityError) as e:
            self.auth.upload_and_verify(rid, manifest, sig, data[:-1] + b"X", COMMIT, RID)
        self.assertEqual(e.exception.code, "package_bytes_differ_from_the_approved_package")
        self.assertEqual(self.http.assets(), {})

    def test_the_http_helpers_refuse_other_hosts_and_never_follow_redirects(self):
        from stynpilot.broker.release_authority import default_fetch
        for url in ("https://evil.example/x", "http://api.github.com/x", "https://api.github.com:444/x",
                    "https://user@api.github.com/x", "https://api.github.com.evil.example/x"):
            with self.assertRaises(AuthorityError):
                default_http("GET", url, {}, None)
        for url in ("https://evil.example/x", "http://objects.githubusercontent.com/x", "https://githubusercontent.com.evil.example/x",
                    "https://user@objects.githubusercontent.com/x", "https://objects.githubusercontent.com:444/x",
                    "https://api.github.com/x"):
            with self.assertRaises(AuthorityError):
                default_fetch(url, 10)

    def test_token_check_reports_whether_it_can_write(self):
        self.assertTrue(self.auth.check_token()["ok"])


@unittest.skipIf(tu is None, "needs the upgrade test harness")
class OneApprovalTests(tu.UpgradeTests):
    """The real executor: challenge, proof, reservation, sign, draft, verify, publish, protected upgrade - behind one approval."""
    def setUp(self):
        tu.UpgradeTests.setUp(self)
        self.deb = Path(self.pkg.deb(VERSION))
        self.machine = FakeMachine(self.deb.read_bytes())
        self.http = FakeGitHub()
        self.auth = Authority(self.tmp / "broker", run=self.machine, http=self.http, build_prefix=["env"], fetch=self.http.fetch)
        # the machine's own signing key IS the trusted key of this test machine
        (self.tmp / "broker" / "release").mkdir(parents=True, exist_ok=True)
        (self.auth.keyfile).write_bytes(release.private_pem(self.signing))
        os.chmod(self.auth.keyfile, 0o600)
        self.auth.set_token("github_pat_" + "C" * 30)
        self.build(authority=self.auth, sleep=lambda s: None)
        self.executor._need_authority()                                        # wires the real package inspection
        self.auth.prepare(COMMIT, VERSION, "0.1.0~dev3")
        self.seen = []
        real = self.http.__call__

        def wrapped(method, url, *a, **k):
            if method in ("POST", "PATCH") and not self.seen:
                self.seen.append(self.executor.runs.status(self.rid)["state"] if getattr(self, "rid", None) else "no-rid")
            result = real(method, url, *a, **k)
            self.publish_into_downloads()
            return result
        self.auth.http = wrapped

    def release_payload(self, note="reviewed", minutes=30):
        from datetime import datetime, timedelta, timezone
        intent = self.executor.release_intent(COMMIT, VERSION, note)
        return {"kind": "release", "owner": tu.OWNER, "device": tu.DEVICE, "intent": intent,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")}

    def publish_into_downloads(self):
        """Make what the fake GitHub received downloadable the way the real GitHub would serve it."""
        for rel in self.http.releases.values():
            base = "https://github.com/bam5693/stynpilot/releases/download/%s/" % rel["tag_name"]
            for name, body in self.http.assets().items():
                self.downloads[base + name] = body

    def go(self, payload=None):
        payload = payload or self.release_payload()
        self.rid = request_id(payload)[0]
        challenge, proof = self.approve(payload)
        return payload, challenge, proof

    def test_the_owner_reads_exact_facts_and_nothing_is_signed_or_published_before_approval(self):
        payload = self.release_payload()
        shown = self.executor.challenge(payload, "approve")
        text = "\n".join(shown["summary"])
        for needle in (COMMIT[:12], payload["intent"]["sha256"], payload["intent"]["key_id"], "ONE approval", "built it twice",
                       "1 passed, 0 failed", "Nothing is signed or published before you approve",
                       "written by an assistant, not verified"):
            self.assertIn(needle, text)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.launched, [])

    def test_approval_signs_publishes_and_starts_the_protected_upgrade_once(self):
        payload, challenge, proof = self.go()
        result = self.executor.release(payload, proof, challenge)
        self.assertEqual((result["pending"], result["to_version"], result["from_version"]), (True, VERSION, "0.1.0~dev3"))
        self.assertEqual(len(self.launched), 1)
        self.assertEqual(set(self.http.assets()), {"stynpilot-v0.1.0-dev4.deb", "release-manifest.json", "release-manifest.json.sig"})
        manifest = json.loads(self.http.assets()["release-manifest.json"])
        self.assertEqual((manifest["git_commit"], manifest["sha256"]), (COMMIT, payload["intent"]["sha256"]))
        self.assertEqual(self.executor._tx_load(self.rid)["state"], "started")
        self.denied("already_decided_or_used", self.executor.release, payload, proof, challenge)        # no replay
        self.assertEqual(len(self.launched), 1)

    def test_the_approval_is_reserved_before_anything_external_happens(self):
        payload, challenge, proof = self.go()
        self.executor.release(payload, proof, challenge)
        self.assertEqual(self.seen, ["running"])                  # at the first change on GitHub the approval was already spent

    def test_a_wrong_proof_or_stale_challenge_publishes_nothing_and_spends_nothing(self):
        payload = self.release_payload()
        self.rid = request_id(payload)[0]
        challenge, _ = self.approve(payload)
        other = self.release_payload(note="a different note")
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, self.proof(other, challenge), challenge)     # signed for a different request
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, "not a token", challenge)
        good = self.proof(payload, challenge)
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, good, "0" * 64)                              # a challenge that was never issued
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.launched, [])
        self.assertEqual(self.executor.runs.status(self.rid)["state"], "not_started")
        self.executor.runs.peek(challenge=challenge, request_id=self.rid, decision="approve")        # still usable

    def test_an_unusable_token_or_a_foreign_tag_is_found_before_the_approval_is_spent(self):
        payload, challenge, proof = self.go()
        self.http.token_status = 401
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.release(payload, proof, challenge)
        self.assertTrue(caught.exception.code.startswith("release_github_token_not_usable"))
        self.http.token_status = 200
        self.http.tags["v0.1.0-dev4"] = "e" * 40
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.release(payload, proof, challenge)
        self.assertEqual(caught.exception.code, "release_tag_exists_for_a_different_commit")
        self.assertEqual(self.executor.runs.status(self.rid)["state"], "not_started")
        self.assertEqual(self.http.releases, {})
        del self.http.tags["v0.1.0-dev4"]
        self.assertEqual(self.executor.release(payload, proof, challenge)["pending"], True)       # same approval, now fine

    def test_an_interrupted_publication_is_resumable_and_never_called_unspent(self):
        payload, challenge, proof = self.go()
        self.http.fail_upload = True
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.release(payload, proof, challenge)
        code = caught.exception.code
        self.assertTrue(code.startswith("release_approval_spent_stopped_after_drafted_resumable_yes"), code)
        self.assertNotIn("unchanged", code)
        self.assertEqual(self.executor.runs.status(self.rid)["state"], "running")
        info = self.executor.status(self.rid)["release"]
        self.assertEqual(info, {"state": "drafted", "approval_spent": True, "resumable": True})
        self.denied("already_decided_or_used", self.executor.release, payload, proof, challenge)   # the approval cannot be reused
        self.assertEqual(self.launched, [])
        self.assertFalse(self.executor.needs_attention())                       # a spent-but-unfinished release is not "damage"
        self.http.fail_upload = False
        result = self.executor.release_resume(self.rid)
        self.assertEqual((result["pending"], result["to_version"]), (True, VERSION))
        self.assertEqual(len(self.launched), 1)
        self.assertEqual(len([c for c in self.http.calls if c[0] == "POST" and c[1].endswith("/releases")]), 1)   # same draft reused
        self.denied("nothing_to_resume", self.executor.release_resume, self.rid)
        self.assertEqual(len(self.launched), 1)

    def test_a_restart_in_the_middle_leaves_the_release_resumable(self):
        payload, challenge, proof = self.go()
        self.http.fail_upload = True
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, proof, challenge)
        self.build(authority=self.auth, sleep=lambda s: None)                  # the installer restarts
        self.assertEqual(self.executor.runs.status(self.rid)["state"], "running")
        self.assertFalse(self.executor.needs_attention())
        self.http.fail_upload = False
        self.assertTrue(self.executor.release_resume(self.rid)["pending"])

    def test_resume_can_only_finish_the_exact_approved_operation(self):
        payload, challenge, proof = self.go()
        self.http.fail_upload = True
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, proof, challenge)
        self.http.fail_upload = False
        pinned = self.executor._tx_copy_path(self.rid)
        os.chmod(pinned, 0o600)
        pinned.write_bytes(b"swapped after the approval")
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.release_resume(self.rid)
        self.assertIn("approved_package_changed", caught.exception.code)
        self.assertEqual(self.launched, [])
        self.assertEqual(self.http.assets(), {})
        for bad in ("short", "g" * 64, None, "../x", "0" * 64):
            with self.assertRaises(ExecutionDenied):
                self.executor.release_resume(bad)

    def interrupted(self):
        payload, challenge, proof = self.go()
        self.http.fail_upload = True
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, proof, challenge)
        self.http.fail_upload = False
        return payload, challenge, proof

    def test_the_approved_package_is_pinned_for_the_whole_transaction(self):
        payload, challenge, proof = self.interrupted()
        # a rebuild of the same commit, or pruning the build folder, cannot change or break a pending release
        self.denied("a_release_is_in_progress", self.executor.release_prepare, COMMIT, VERSION)
        import shutil as _sh
        _sh.rmtree(self.tmp / "broker/release/builds" / COMMIT)
        result = self.executor.release_resume(self.rid)
        self.assertTrue(result["pending"])
        self.assertEqual(self.http.assets()["stynpilot-v0.1.0-dev4.deb"], self.deb.read_bytes())

    def test_the_pinned_copy_is_dropped_once_the_upgrade_has_its_own(self):
        payload, challenge, proof = self.go()
        self.executor.release(payload, proof, challenge)
        self.assertFalse(self.executor._tx_copy_path(self.rid).exists())

    def test_settling_an_upgrade_that_raises_attention_stops_the_release_gate(self):
        payload, challenge, proof = self.interrupted()
        calls = []

        def settle():
            calls.append(1)
            self.executor._attention("d" * 64, None, "upgrade_worker_vanished_without_a_result", None)
        self.executor._settle_upgrades = settle
        self.assertIn("owner_intervention_required", self.expect_denied(self.executor.release_resume, self.rid))
        self.assertEqual(calls, [1])
        self.assertEqual(self.http.assets(), {})

    def test_a_pinned_package_that_changes_is_caught_right_before_upload(self):
        payload, challenge, proof = self.interrupted()
        pinned = self.executor._tx_copy_path(self.rid)
        os.chmod(pinned, 0o600)
        pinned.write_bytes(pinned.read_bytes()[:-1] + b"X")                     # same size, different bytes
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.release_resume(self.rid)
        self.assertIn("approved_package_changed", caught.exception.code)
        self.assertEqual(self.http.assets(), {})

    def test_resume_respects_attention_other_upgrades_revoked_keys_and_the_installed_version(self):
        payload, challenge, proof = self.interrupted()
        # unresolved machine attention
        self.executor._attention("e" * 64, None, "something_broke", None)
        self.assertIn("owner_intervention_required", self.expect_denied(self.executor.release_resume, self.rid))
        for f in (self.tmp / "broker" / "attention").glob("*"):
            f.unlink()
        self.assertFalse(self.executor.needs_attention())
        # another change is running
        self.executor.runs.consume(challenge=self.executor.runs.issue("f" * 64, "approve"), request_id="f" * 64, decision="approve",
                                   proof="x", kind="install")
        self.assertIn("another_change_is_still_running", self.expect_denied(self.executor.release_resume, self.rid))
        self.executor.runs.finish("f" * 64, "done", {"ok": True})
        # the signing key was revoked
        keys = self.executor.upgrader._keys
        self.executor.upgrader._keys = {"1" * 16: release.new_private_key().public_key()}
        self.assertIn("release_key_not_trusted_by_this_machine", self.expect_denied(self.executor.release_resume, self.rid))
        self.executor.upgrader._keys = keys
        # the machine already runs this version or newer
        real = self.executor.upgrader.installed_version
        self.executor.upgrader.installed_version = lambda: "0.1.0~dev9"
        self.assertIn("not_newer_than_installed", self.expect_denied(self.executor.release_resume, self.rid))
        self.executor.upgrader.installed_version = real
        self.assertEqual(self.http.assets(), {})
        self.assertEqual(self.launched, [])
        self.assertTrue(self.executor.release_resume(self.rid)["pending"])      # all clear: it finishes

    def expect_denied(self, fn, *args):
        with self.assertRaises(ExecutionDenied) as caught:
            fn(*args)
        return caught.exception.code

    def test_a_crash_between_spending_the_approval_and_recording_it_is_recoverable(self):
        payload, challenge, proof = self.go()
        real = self.executor._tx_save

        def crash(tx):
            if tx["state"] == "reserved":
                raise RuntimeError("power cut")
            return real(tx)
        self.executor._tx_save = crash
        with self.assertRaises(RuntimeError):
            self.executor.release(payload, proof, challenge)
        self.executor._tx_save = real
        self.assertEqual(self.executor.runs.status(self.rid)["state"], "running")          # the approval IS spent
        self.assertEqual(self.executor._tx_load(self.rid)["state"], "authorized")
        self.assertEqual(self.executor.status(self.rid)["release"]["resumable"], True)
        self.build(authority=self.auth, sleep=lambda s: None)                              # and the installer restarts
        self.assertFalse(self.executor.needs_attention())
        self.assertTrue(self.executor.release_resume(self.rid)["pending"])
        self.assertEqual(len(self.launched), 1)

    def test_a_crash_after_the_draft_is_made_but_before_it_is_recorded_reuses_that_draft(self):
        payload, challenge, proof = self.go()
        real = self.executor._tx_save

        def crash(tx):
            if tx["state"] == "drafted":
                raise OSError("disk went away")
            return real(tx)
        self.executor._tx_save = crash
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.release(payload, proof, challenge)
        self.assertIn("stopped_after_signed_resumable_yes", caught.exception.code)
        self.executor._tx_save = real
        self.assertTrue(self.executor.release_resume(self.rid)["pending"])
        self.assertEqual(len(self.http.releases), 1)                                       # no second draft, nothing adopted blindly

    def test_a_crash_between_upgrade_preparation_and_worker_launch_resumes_without_blame(self):
        payload, challenge, proof = self.go()
        calls = []
        real = self.executor.upgrader.launch

        def die(rid, job):
            calls.append(1)
            raise RuntimeError("killed before the worker started")
        self.executor.upgrader.launch = die
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.release(payload, proof, challenge)
        self.assertIn("stopped_after_published_resumable_yes", caught.exception.code)
        job = self.executor.upgrader.job_dir(self.rid)
        self.assertTrue((job / "job.json").exists() and not (job / "unit").exists())
        self.executor.upgrader.launch = real
        self.build(authority=self.auth, sleep=lambda s: None)                              # restart: the half-started job is not "vanished"
        self.assertFalse(self.executor.needs_attention())
        self.assertEqual(self.executor.runs.status(self.rid)["state"], "running")
        self.assertTrue(self.executor.release_resume(self.rid)["pending"])
        self.assertEqual(len(self.launched), 1)
        self.assertEqual(len(self.http.releases), 1)

    def test_an_old_spent_release_cannot_be_resumed_and_is_closed_honestly(self):
        import time as _time
        payload, challenge, proof = self.go()
        self.http.fail_upload = True
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, proof, challenge)
        self.http.fail_upload = False
        self.executor.clock_now = lambda: _time.time() + 25 * 3600
        self.denied("release_approval_expired_start_again_with_a_new_approval", self.executor.release_resume, self.rid)
        record = self.executor.runs.status(self.rid)
        self.assertEqual(record["state"], "failed")
        self.assertTrue(record["result"]["approval_spent"])
        self.assertFalse(record["result"]["resumable"])
        self.assertEqual(self.launched, [])

    def test_a_github_failure_never_starts_the_upgrade(self):
        payload, challenge, proof = self.go()
        self.http.fail_upload = True
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, proof, challenge)
        self.assertEqual(self.launched, [])
        self.assertTrue(self.http.releases[next(iter(self.http.releases))]["draft"])           # nothing public

    def test_a_changed_intent_is_refused_before_anyone_is_asked(self):
        for field, value in (("sha256", "0" * 64), ("commit", "d" * 40), ("tests_failed", 3), ("tests_passed", 99),
                             ("key_id", "0" * 16), ("version", "0.1.0~dev9"), ("from_min", "0.1.0~dev3")):
            payload = self.release_payload()
            payload["intent"][field] = value
            with self.assertRaises(ExecutionDenied, msg=field):
                self.executor.challenge(payload, "approve")
        extra = self.release_payload()
        extra["intent"]["extra"] = 1
        with self.assertRaises(ExecutionDenied):
            self.executor.challenge(extra, "approve")
        stray = dict(self.release_payload(), surprise=1)
        with self.assertRaises(ExecutionDenied):
            self.executor.challenge(stray, "approve")
        self.assertEqual(self.http.calls, [])

    def test_a_key_this_machine_does_not_trust_cannot_even_be_requested(self):
        self.executor.upgrader._keys = {"1" * 16: release.new_private_key().public_key()}
        self.denied("release_key_not_trusted_by_this_machine", self.executor.challenge, self.release_payload(), "approve")

    def test_the_trusted_keys_are_read_fresh_each_time_they_are_needed(self):
        self.executor.upgrader._keys = None
        calls = []
        real = release.load_trusted_keys
        release.load_trusted_keys = lambda *a, **k: calls.append(1) or {"k": object()}
        try:
            self.executor.upgrader.keys
            self.executor.upgrader.keys
        finally:
            release.load_trusted_keys = real
        self.assertEqual(len(calls), 2)

    def test_not_newer_expired_and_unconfigured_cases(self):
        stale = self.release_payload(minutes=-5)
        self.denied("plan_invalid_or_expired", self.executor.challenge, stale, "approve")
        long = self.release_payload(minutes=120)
        self.denied("plan_invalid_or_expired", self.executor.challenge, long, "approve")
        self.build(sleep=lambda s: None)                               # no authority configured
        self.denied("release_publishing_not_configured", self.executor.challenge, {"kind": "release"}, "approve")
        self.denied("release_publishing_not_configured", self.executor.release_prepare, COMMIT, VERSION)
        self.denied("release_publishing_not_configured", self.executor.release_resume, "0" * 64)


@unittest.skipIf(tu is None, "needs the upgrade test harness")
class TrustAndConsoleTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = Path(t.name)
        os.chmod(self.tmp, 0o700)
        self.package_key = release.new_private_key()
        self.keys = self.tmp / "keys.json"
        self.keys.write_text(json.dumps({"keys": [release.public_entry(self.package_key)]}))
        self.addendum = self.tmp / "addendum.json"
        self.auth = Authority(self.tmp / "state", run=lambda *a, **k: (1, ""), http=lambda *a, **k: (200, b'{"permissions": {"push": true}}'), build_prefix=["env"])
        self.out = []

    def trusted(self):
        return release.load_trusted_keys(self.keys, addendum=self.addendum)

    def test_console_init_creates_the_key_and_makes_the_machine_trust_it_only_then(self):
        self.assertEqual(len(self.trusted()), 1)
        self.assertEqual(release_console.init(self.auth, self.addendum, keys_file=self.keys, out=self.out.append), 0)
        mine = self.auth.key_entry()["key_id"]
        self.assertIn(mine, self.trusted())
        self.assertEqual(len(self.trusted()), 2)
        self.assertEqual(release_console.init(self.auth, self.addendum, keys_file=self.keys, out=self.out.append), 0)          # idempotent
        self.assertEqual(len(self.trusted()), 2)

    def test_a_revoked_key_stops_being_trusted_and_a_damaged_addendum_is_an_error(self):
        release_console.init(self.auth, self.addendum, keys_file=self.keys, out=self.out.append)
        mine = self.auth.key_entry()["key_id"]
        data = json.loads(self.addendum.read_text())
        data["revoked"] = [mine, release.public_entry(self.package_key)["key_id"]]
        self.addendum.write_text(json.dumps(data))
        with self.assertRaises(release.ReleaseError) as e:
            self.trusted()
        self.assertEqual(e.exception.code, "no_trusted_keys")                     # both revoked: nothing left
        self.addendum.write_text("{not json")
        with self.assertRaises(release.ReleaseError) as e:
            self.trusted()
        self.assertEqual(e.exception.code, "trusted_keys_addendum_unreadable")
        self.addendum.write_text(json.dumps({"keys": [], "revoked": [], "extra": 1}))
        with self.assertRaises(release.ReleaseError):
            self.trusted()
        self.addendum.write_text(json.dumps({"keys": [{"key_id": "0" * 16, "public": release.public_entry(self.package_key)["public"]}]}))
        with self.assertRaises(release.ReleaseError):
            self.trusted()

    def test_init_never_silently_undoes_a_revocation(self):
        release_console.init(self.auth, self.addendum, keys_file=self.keys, out=self.out.append)
        mine = self.auth.key_entry()["key_id"]
        data = json.loads(self.addendum.read_text())
        data["revoked"] = [mine]
        self.addendum.write_text(json.dumps(data, sort_keys=True))
        before = self.addendum.read_text()
        self.assertEqual(release_console.init(self.auth, self.addendum, keys_file=self.keys, out=self.out.append), 1)
        self.assertEqual(self.addendum.read_text(), before)
        self.assertNotIn(mine, self.trusted())
        self.assertIn("revoked", "\n".join(self.out))

    def test_init_checks_that_the_machine_really_trusts_the_key_it_just_wrote(self):
        self.keys.write_text("{broken")
        self.assertEqual(release_console.init(self.auth, self.addendum, keys_file=self.keys, out=self.out.append), 1)
        self.assertIn("could not be re-read", "\n".join(self.out))

    def test_the_token_needs_a_terminal_and_a_well_formed_value(self):
        token = "github_pat_" + "D" * 30
        self.assertEqual(release_console.set_token(self.auth, getpass_fn=lambda _p: token, is_tty=False, out=self.out.append), 2)
        self.assertFalse(self.auth.tokenfile.exists())
        self.assertEqual(release_console.set_token(self.auth, getpass_fn=lambda _p: "bad token", is_tty=True, out=self.out.append), 1)
        self.assertFalse(self.auth.tokenfile.exists())
        self.assertEqual(release_console.set_token(self.auth, getpass_fn=lambda _p: token, is_tty=True, out=self.out.append), 0)
        self.assertTrue(self.auth.tokenfile.exists())
        self.assertNotIn(token, "\n".join(self.out))

    def test_status_never_prints_secrets(self):
        release_console.init(self.auth, self.addendum, keys_file=self.keys, out=self.out.append)
        self.auth.set_token("github_pat_" + "E" * 30)
        release_console.status(self.auth, self.addendum, keys_file=self.keys, out=self.out.append)
        text = "\n".join(self.out)
        self.assertNotIn("E" * 30, text)
        self.assertNotIn("PRIVATE", text)
        self.assertIn("trusts the signing key: yes", text)


@unittest.skipIf(tu is None, "needs the upgrade test harness")
class ConfigTests(unittest.TestCase):
    BASE = {"issuer": "https://x.us.auth0.com/", "approval_client_id": "c", "owner": "o", "device": "d", "owner_uid": 1000,
            "state_dir": "/tmp/s", "socket_path": "/tmp/s.sock"}

    def put(self, path, data):
        if path.exists():
            path.unlink()
        path.write_text(json.dumps(data))
        os.chmod(path, 0o600)

    def test_release_settings_live_in_their_own_file_and_installer_json_keeps_dev14s_shape(self):
        from stynpilot.service import ConfigError, InstallerConfig, build_authority
        with tempfile.TemporaryDirectory() as folder:
            main, side = Path(folder) / "installer.json", Path(folder) / "release.json"
            self.put(main, self.BASE)
            cfg = InstallerConfig.from_file(main)
            self.assertIsNone(cfg.release_build_user)
            self.assertIsNone(build_authority(cfg))                                   # default: publishing is off
            self.put(main, dict(self.BASE, build_user="x"))
            with self.assertRaises(ConfigError):
                InstallerConfig.from_file(main)
            self.put(main, self.BASE)
            for bad in ("root", "Bad Name", "", 5, "a;b"):
                self.put(side, {"build_user": bad})
                with self.assertRaises(ConfigError):
                    InstallerConfig.from_file(main)
            self.put(side, {"build_user": "no-such-account-xyz"})
            with self.assertRaises(ConfigError) as e:
                build_authority(InstallerConfig.from_file(main), state_dir=Path(folder))
            self.assertEqual(str(e.exception), "release_build_user_does_not_exist")

    def test_only_the_network_steps_of_the_real_builder_sandbox_can_resolve_names_and_only_through_one_file(self):
        import pwd
        from stynpilot.service import InstallerConfig, build_authority
        try:
            pwd.getpwnam("nobody")
        except KeyError:
            self.skipTest("no 'nobody' account here")
        with tempfile.TemporaryDirectory() as folder:
            main, side = Path(folder) / "installer.json", Path(folder) / "release.json"
            self.put(main, self.BASE)
            self.put(side, {"build_user": "nobody"})
            auth = build_authority(InstallerConfig.from_file(main), state_dir=Path(folder))
            job, argv, ws = "a" * 24, ["/usr/bin/git", "fetch"], "/var/lib/stynpilot-build/" + "c" * 40
            limits = dict(seconds=60, memory_mb=512, tasks=64)
            props = lambda c: [c[i + 1] for i, a in enumerate(c) if a == "-p"]
            online = props(auth.sandbox(job, argv, ws, network=True, **limits))
            offline = props(auth.sandbox(job, argv, ws, network=False, **limits))
            self.assertIn("BindReadOnlyPaths=-/run/systemd/resolve/stub-resolv.conf", online)
            self.assertIn("PrivateNetwork=no", online)
            self.assertIn("TemporaryFileSystem=/run:mode=0755,nosuid,nodev,size=%dM" % __import__("stynpilot.runner", fromlist=["x"]).RUN_MB, online)
            self.assertFalse([p for p in offline if p.startswith("BindReadOnlyPaths") or p.startswith("BindPaths=/run")])
            self.assertIn("PrivateNetwork=yes", offline)
            # never the whole /run or the resolver folder (it holds sockets), on any step
            for each in (online, offline):
                self.assertFalse([p for p in each if re.fullmatch(r"Bind(ReadOnly)?Paths=-?/run(/systemd(/resolve)?)?/?", p)])


if __name__ == "__main__":
    unittest.main()
