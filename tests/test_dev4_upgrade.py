"""dev4 self-upgrade: signed releases, package inspection, backups, the detached worker and automatic rollback.

The package checks use REAL ``dpkg-deb`` on small throwaway packages and a private dpkg database, so no root and no
system change is needed. The worker is tested against a simulated machine (every failure mode); the real
``dpkg -i`` / downgrade path is exercised by tests/test_dev4_real_dpkg.py when run as root in a disposable root.
"""
import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot.broker import apt
    from stynpilot.broker.executor import ExecutionDenied, Executor
    from stynpilot.broker.proof import ProofVerifier, decision_nonce
except ImportError:          # pragma: no cover
    jwt = None

from stynpilot import release
from stynpilot.identity import account_id
from stynpilot.requests import request_id
from stynpilot.upgrade_worker import Worker

ISS, APP, SUB = "https://issuer.example.test/", "approval-app-client", "auth0|test-owner"
OWNER = account_id(verified_issuer=ISS, verified_subject=SUB)
DEVICE = "dtdev_TESTONLYliveDevice"
DEPENDS = "python3 (>= 3.11), python3-cryptography, ca-certificates"


def have_dpkg():
    return subprocess.run(["which", "dpkg-deb"], capture_output=True).returncode == 0


class Pkg:
    """Builds throwaway stynpilot packages and a fake 'installed' system for them."""

    def __init__(self, tmp):
        self.tmp, self.count = Path(tmp), 0

    def deb(self, version, *, files=None, depends=DEPENDS, scripts=(), package="stynpilot", arch="all", modes=None):
        self.count += 1
        stage = self.tmp / ("stage%d" % self.count)
        content = {"usr/lib/stynpilot/lib/stynpilot/__init__.py": "VERSION = %r\n" % version,
                   "usr/bin/stynpilot": "#!/bin/sh\necho %s\n" % version,
                   "usr/share/doc/stynpilot/README.md": "docs %s\n" % version}
        content.update(files or {})
        sums = []
        for rel, text in sorted(content.items()):
            path = stage / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            path.chmod((modes or {}).get(rel, 0o755 if rel == "usr/bin/stynpilot" else 0o644))
            sums.append("%s  %s" % (hashlib.md5(text.encode()).hexdigest(), rel))
        for d in [stage, *stage.rglob("*")]:
            if d.is_dir():
                d.chmod(0o755)
        control = stage / "DEBIAN"
        control.mkdir()
        control.chmod(0o755)
        (control / "control").write_text("Package: %s\nVersion: %s\nSection: admin\nPriority: optional\nArchitecture: %s\n"
                                         "Depends: %s\nMaintainer: t <t@invalid>\nDescription: test\n"
                                         % (package, version, arch, depends))
        (control / "md5sums").write_text("\n".join(sums) + "\n")
        for name in scripts:
            (control / name).write_text("#!/bin/sh\nexit 0\n")
            (control / name).chmod(0o755)
        out = self.tmp / ("stynpilot_%s_%d.deb" % (version.replace("~", "-"), self.count))
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Znone", "--build", str(stage), str(out)], check=True,
                       capture_output=True)
        return out

    def install_fake(self, root, version, depends=DEPENDS, files=None):
        """A private 'installed' state: dpkg database plus the package's files under ``root``."""
        admin = root / "var/lib/dpkg"
        (admin / "info").mkdir(parents=True, exist_ok=True)
        (admin / "updates").mkdir(exist_ok=True)
        (admin / "status").write_text(
            "Package: stynpilot\nStatus: install ok installed\nPriority: optional\nSection: admin\nMaintainer: t <t@invalid>\n"
            "Architecture: all\nVersion: %s\nDepends: %s\nDescription: test\n\n" % (version, depends))
        (admin / "available").write_text("")
        content = {"usr/lib/stynpilot/lib/stynpilot/__init__.py": "VERSION = %r\n" % version,
                   "usr/bin/stynpilot": "#!/bin/sh\necho %s\n" % version,
                   "usr/share/doc/stynpilot/README.md": "docs %s\n" % version}
        content.update(files or {})
        sums = []
        for rel, text in sorted(content.items()):
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            path.chmod(0o755 if rel == "usr/bin/stynpilot" else 0o644)
            sums.append("%s  %s" % (hashlib.md5(text.encode()).hexdigest(), rel))
        (admin / "info/stynpilot.md5sums").write_text("\n".join(sums) + "\n")
        return content


@unittest.skipIf(jwt is None or not have_dpkg(), "needs PyJWT, cryptography and dpkg-deb")
class UpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key(), as_dict=True)
        public.update(kid="k1", use="sig", alg="RS256")
        cls.jwks = {"keys": [public]}

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.pkg = Pkg(self.tmp)
        self.root = self.tmp / "sys"
        self.installed = self.pkg.install_fake(self.root, "0.1.0~dev3")
        self.signing = release.new_private_key()
        entry = release.public_entry(self.signing)
        keyfile = self.tmp / "keys.json"
        keyfile.write_text(json.dumps({"keys": [entry]}))
        self.keys = release.load_trusted_keys(keyfile)
        self.key_id = entry["key_id"]
        self.downloads, self.launched = {}, []
        self.verifier = ProofVerifier(issuer=ISS, approval_client_id=APP, jwks=self.jwks)
        self.build()

    def build(self, **extra):
        options = {"root": self.root, "query_extra": ["--admindir=%s" % (self.root / "var/lib/dpkg")],
                   "dpkg_extra": [], "config_files": [], "owner_user": "nobody", "restart": False, "doctor": False}
        self.executor = Executor(
            state_dir=self.tmp / "broker", owner=OWNER, device=DEVICE, verifier=self.verifier, run=apt.real_run,
            require_root=False, owner_uid=os.getuid(), release_keys=self.keys,
            fetch_release=lambda url, limit: self.downloads[url],
            launch_worker=lambda rid, job: self.launched.append((rid, job)) or ("stynpilot-upgrade-" + rid[:12]),
            upgrade_options=options, **extra)

    # -- helpers ------------------------------------------------------------------------------
    def release_for(self, deb, *, sign=True, key=None, **changes):
        data = Path(deb).read_bytes()
        version = subprocess.run(["dpkg-deb", "-f", str(deb), "Version"], capture_output=True, text=True).stdout.strip()
        tag = release.tag_for_version(version)
        manifest = {"schema": 1, "package": "stynpilot", "version": version, "tag": tag, "asset": "stynpilot-%s.deb" % tag,
                    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "git_commit": "a" * 40, "from_min": "",
                    "created": "2026-11-23T12:00:00Z", "notes": ["test release"]}
        manifest.update(changes)
        signature = release.sign(manifest, key or self.signing) if sign else "A" * 86 + "=="
        self.downloads[release.download_url(manifest)] = data
        return manifest, signature

    def payload(self, manifest, signature, minutes=60):
        return {"kind": "upgrade", "software": "stynpilot-self", "owner": OWNER, "device": DEVICE, "manifest": manifest,
                "signature": signature,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")}

    def proof(self, payload, challenge, decision="approve"):
        rid, _ = request_id(payload)
        now = int(time.time())
        claims = {"iss": ISS, "aud": APP, "sub": SUB, "iat": now, "exp": now + 300, "auth_time": now - 5,
                  "nonce": decision_nonce(decision, rid, rid, challenge)}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def approve(self, payload):
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        return challenge, self.proof(payload, challenge)

    def denied(self, code, fn, *args):
        with self.assertRaises(ExecutionDenied) as caught:
            fn(*args)
        self.assertEqual(caught.exception.code, code)

    def good(self, version="0.1.0~dev4", **kw):
        deb = self.pkg.deb(version, **kw)
        manifest, signature = self.release_for(deb)
        return self.payload(manifest, signature)

    # -- the plan the owner reads ---------------------------------------------------------------
    def test_summary_names_version_checksum_key_and_rollback(self):
        payload = self.good()
        shown = self.executor.challenge(payload, "approve")["summary"]
        text = "\n".join(shown)
        self.assertIn("from 0.1.0~dev3 to version 0.1.0~dev4", text)
        self.assertIn(payload["manifest"]["sha256"], text)
        self.assertIn(self.key_id, text)
        self.assertIn("automatically puts the current version back", text)
        self.assertIn("github.com/bam5693/stynpilot", text)

    def test_unsigned_tampered_or_wrongly_signed_releases_are_refused_before_anyone_is_asked(self):
        deb = self.pkg.deb("0.1.0~dev4")
        manifest, signature = self.release_for(deb)
        self.denied("signature_not_trusted", self.executor.challenge,
                    self.payload({**manifest, "sha256": "b" * 64}, signature), "approve")        # edited after signing
        self.denied("signature_not_trusted", self.executor.challenge,
                    self.payload(manifest, release.sign(manifest, release.new_private_key())), "approve")  # unknown key
        self.denied("signature_malformed", self.executor.challenge, self.payload(manifest, "not base64!"), "approve")
        self.denied("manifest_invalid", self.executor.challenge, self.payload({**manifest, "extra": 1}, signature), "approve")
        self.denied("manifest_invalid_tag", self.executor.challenge,
                    self.payload({**manifest, "tag": "../x"}, signature), "approve")

    def test_a_signed_manifest_cannot_point_anywhere_but_the_pinned_repository(self):
        deb = self.pkg.deb("0.1.0~dev4")
        manifest, _ = self.release_for(deb)
        self.assertEqual(release.download_url(manifest),
                         "https://github.com/bam5693/stynpilot/releases/download/v0.1.0-dev4/stynpilot-v0.1.0-dev4.deb")
        for bad in ({"asset": "../../evil.deb"}, {"asset": "x.sh"}, {"tag": "v1/../../x"}):
            with self.assertRaises(release.ReleaseError):
                release.download_url({**manifest, **bad})

    def test_only_a_newer_version_with_a_satisfied_minimum_is_accepted(self):
        for version, code in (("0.1.0~dev3", "not_newer_than_installed"), ("0.1.0~dev2", "not_newer_than_installed")):
            deb = self.pkg.deb(version)
            manifest, signature = self.release_for(deb)
            self.denied(code, self.executor.challenge, self.payload(manifest, signature), "approve")
        deb = self.pkg.deb("0.1.0~dev5")
        manifest, signature = self.release_for(deb, from_min="0.1.0~dev4")
        self.denied("installed_version_too_old_for_this_release", self.executor.challenge,
                    self.payload(manifest, signature), "approve")

    def test_plan_must_be_for_this_owner_and_device_and_not_expired(self):
        payload = self.good()
        self.denied("plan_invalid_or_expired", self.executor.challenge, {**payload, "owner": "acct_" + "b" * 40}, "approve")
        self.denied("plan_invalid_or_expired", self.executor.challenge, {**payload, "device": "dtdev_OTHERdevice1"}, "approve")
        self.denied("plan_invalid_or_expired", self.executor.challenge, {**payload, "expires_at": "2020-01-01T00:00:00Z"}, "approve")
        self.denied("plan_invalid_or_expired", self.executor.challenge, {**payload, "software": "htop"}, "approve")
        self.denied("plan_invalid_or_expired", self.executor.challenge, {**payload, "kind": "upgrade", "extra": 1}, "approve")

    # -- the package itself ---------------------------------------------------------------------
    def attempt(self, **kw):
        payload = self.good(**kw)
        challenge, token = self.approve(payload)
        return payload, lambda: self.executor.upgrade(payload, token, challenge)

    def test_dangerous_packages_are_refused_and_nothing_is_started(self):
        cases = {
            "package_has_install_scripts_or_extra_control_files": {"scripts": ("postinst",)},
            "package_path_not_allowed": {"files": {"etc/cron.d/evil": "* * * * * root x\n"}},
            "package_changes_dependencies_not_allowed_here": {"depends": DEPENDS + ", curl"},
            "package_contains_a_disallowed_file_type_or_owner": {"modes": {"usr/bin/stynpilot": 0o4755}},
        }
        for code, kw in cases.items():
            payload, go = self.attempt(**kw)
            self.denied(code, go)
            self.assertEqual(self.launched, [], code)
            self.assertFalse(self.executor.upgrader.job_dir(request_id(payload)[0]).exists(), code)
            self.assertEqual(self.executor.status(request_id(payload)[0])["state"], "not_started", code)

    def test_wrong_package_name_architecture_or_version_is_refused(self):
        deb = self.pkg.deb("0.1.0~dev4", package="other")
        manifest, signature = self.release_for(deb)
        payload = self.payload(manifest, signature)
        challenge, token = self.approve(payload)
        self.denied("package_identity_differs_from_manifest", self.executor.upgrade, payload, token, challenge)
        deb = self.pkg.deb("0.1.0~dev4")
        manifest, signature = self.release_for(deb, version="0.1.0~dev6")        # signed claim differs from the package
        payload = self.payload(manifest, signature)
        challenge, token = self.approve(payload)
        self.denied("package_identity_differs_from_manifest", self.executor.upgrade, payload, token, challenge)

    def test_a_download_that_differs_from_the_signed_manifest_is_refused(self):
        deb = self.pkg.deb("0.1.0~dev4")
        manifest, signature = self.release_for(deb)
        self.downloads[release.download_url(manifest)] = Path(self.pkg.deb("0.1.0~dev4", files={"usr/bin/x": "evil"})).read_bytes()
        payload = self.payload(manifest, signature)
        challenge, token = self.approve(payload)
        self.denied("download_does_not_match_signed_manifest", self.executor.upgrade, payload, token, challenge)
        self.assertEqual(self.launched, [])

    # -- approval is required ---------------------------------------------------------------------
    def test_without_the_owners_proof_nothing_is_downloaded_backed_up_or_started(self):
        payload = self.good()
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        other = self.good("0.1.0~dev9")
        wrong = self.proof(other, challenge)                            # a proof bound to a different request
        self.assertTrue(self.code_of(lambda: self.executor.upgrade(payload, wrong, challenge)))
        self.assertEqual(self.launched, [])
        self.assertEqual(list((self.tmp / "broker/upgrade-backups").glob("*")), [])
        self.assertFalse(self.executor.upgrader.job_dir(request_id(payload)[0]).exists())
        self.assertEqual(self.executor.status(request_id(payload)[0])["state"], "not_started")

    def code_of(self, fn):
        try:
            fn()
        except ExecutionDenied as denied:
            return denied.code
        self.fail("expected a refusal")

    def test_a_deny_decision_works_and_blocks_the_request_forever(self):
        payload = self.good()
        challenge = self.executor.challenge(payload, "deny")["challenge"]
        token = self.proof(payload, challenge, "deny")
        self.assertTrue(self.executor.deny(payload, token, challenge)["denied_by_owner"])
        self.denied("already_decided_or_used", self.executor.challenge, payload, "approve")

    # -- the approved upgrade ---------------------------------------------------------------------
    def test_approved_upgrade_makes_backups_a_proven_rollback_copy_and_starts_one_worker(self):
        payload, go = self.attempt()
        rid = request_id(payload)[0]
        result = go()
        self.assertEqual((result["ok"], result["pending"], result["from_version"], result["to_version"]),
                         (None, True, "0.1.0~dev3", "0.1.0~dev4"))
        self.assertEqual(len(self.launched), 1)
        job = self.executor.upgrader.job_dir(rid)
        data = json.loads((job / "job.json").read_text())
        self.assertEqual(data["from_version"], "0.1.0~dev3")
        self.assertEqual(data["previous_copy"], "repacked_from_installed_files")
        # the rollback copy IS the installed version, byte for byte on every file
        out = self.tmp / "extract"
        subprocess.run(["dpkg-deb", "-x", str(job / "previous.deb"), str(out)], check=True)
        for rel, text in self.installed.items():
            self.assertEqual((out / rel).read_text(), text)
        self.assertEqual(subprocess.run(["dpkg-deb", "-f", str(job / "previous.deb"), "Version"], capture_output=True,
                                        text=True).stdout.strip(), "0.1.0~dev3")
        self.assertEqual(data["new_sha256"], payload["manifest"]["sha256"])
        # the installer's own records were backed up and verify
        backups = list((self.tmp / "broker/upgrade-backups").glob("records-*.tar"))
        self.assertEqual(len(backups), 1)
        from stynpilot import backup
        backup.read_backup(backups[0], expected_kind="root")                # re-reads and verifies every hash
        # the approval is consumed: the run is 'running', and the same approval cannot start a second worker
        self.assertEqual(self.executor.status(rid)["state"], "running")
        self.assertTrue(self.code_of(lambda: self.executor.challenge(payload, "approve")))   # cannot be decided again

    def test_while_an_upgrade_runs_nothing_else_can_be_decided_or_changed(self):
        payload, go = self.attempt()
        go()
        other = self.good("0.1.0~dev5")
        self.denied("an_upgrade_is_still_running", self.executor.challenge, other, "approve")

    def test_a_tampered_installation_gives_no_rollback_copy_so_no_upgrade(self):
        (self.root / "usr/bin/stynpilot").write_text("#!/bin/sh\necho hacked\n")
        payload, go = self.attempt()
        self.denied("installed_files_modified_so_no_trustworthy_rollback_copy", go)
        self.assertEqual(self.launched, [])

    def test_the_exact_package_kept_from_the_last_upgrade_is_preferred_as_the_rollback(self):
        old = self.pkg.deb("0.1.0~dev3", files={"usr/share/doc/stynpilot/KEPT": "kept original\n"})
        (self.tmp / "broker/kept").mkdir(exist_ok=True)
        (self.tmp / "broker/kept/stynpilot_0.1.0~dev3_all.deb").write_bytes(old.read_bytes())
        payload, go = self.attempt()
        go()
        data = json.loads((self.executor.upgrader.job_dir(request_id(payload)[0]) / "job.json").read_text())
        self.assertEqual(data["previous_copy"], "kept_original")

    # -- settling the outcome -----------------------------------------------------------------------
    def finish_with(self, payload, result):
        job = self.executor.upgrader.job_dir(request_id(payload)[0])
        (job / "result.json").write_text(json.dumps(result))
        return job

    def test_a_successful_result_settles_done_and_keeps_the_new_package_for_the_next_rollback(self):
        payload, go = self.attempt()
        go()
        rid = request_id(payload)[0]
        self.finish_with(payload, {"ok": True, "installed": "0.1.0~dev4", "from_version": "0.1.0~dev3",
                                   "to_version": "0.1.0~dev4", "rolled_back": False, "changed_anything": True})
        status = self.executor.status(rid)
        self.assertEqual(status["state"], "done")
        self.assertTrue((self.tmp / "broker/kept/stynpilot_0.1.0~dev4_all.deb").is_file())

    def test_a_rolled_back_failure_is_reported_failed_and_leaves_the_installer_usable(self):
        payload, go = self.attempt()
        go()
        rid = request_id(payload)[0]
        self.finish_with(payload, {"ok": False, "stopped": "health_check_failed", "rolled_back": True,
                                   "changed_anything": True, "from_version": "0.1.0~dev3", "to_version": "0.1.0~dev4"})
        self.assertEqual(self.executor.status(rid)["state"], "failed")
        self.assertEqual(self.executor.needs_attention(), [])
        self.executor.challenge(self.good("0.1.0~dev5"), "approve")          # a later request is allowed

    def test_an_unrecovered_failure_blocks_everything_until_the_owner_looks(self):
        cfg = self.tmp / "installer.json"
        cfg.write_text('{"owner":"x"}')
        self.executor.upgrader.config_files = [str(cfg)]
        payload, go = self.attempt()
        go()
        cfg.write_text('{"owner":"CHANGED"}')                   # the machine is NOT provably back as it was
        rid = request_id(payload)[0]
        self.finish_with(payload, {"ok": False, "stopped": "health_check_failed", "rolled_back": False,
                                   "needs_owner_intervention": True, "changed_anything": True})
        self.assertEqual(self.executor.status(rid)["state"], "needs_owner_intervention")
        self.assertEqual(len(self.executor.needs_attention()), 1)
        self.denied("owner_intervention_required", self.executor.challenge, self.good("0.1.0~dev5"), "approve")

    def failed_unrecovered(self, **result):
        payload, go = self.attempt()
        go()
        rid = request_id(payload)[0]
        data = {"ok": False, "stopped": "health_check_failed", "rolled_back": False, "needs_owner_intervention": True,
                "changed_anything": True}
        data.update(result)
        self.finish_with(payload, data)
        self.assertEqual(self.executor.status(rid)["state"], "needs_owner_intervention")
        return rid

    def test_a_stale_health_check_failure_is_released_only_after_the_real_machine_proves_healthy_and_is_kept_for_audit(self):
        import contextlib
        import io
        rid = self.failed_unrecovered()                           # the dev5 shape: probe failed, machine actually fine
        record = json.loads((self.tmp / ("broker/attention/%s.json" % rid)).read_text())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.executor.needs_attention(), [])
        self.assertIn("attention_released request=%s" % rid[:12], err.getvalue())    # visible in the journal for verification
        self.assertFalse((self.tmp / ("broker/attention/%s.json" % rid)).exists())
        kept = json.loads((self.tmp / ("broker/attention-resolved/%s.json" % rid)).read_text())
        for key, value in record.items():                         # the original record is preserved word for word
            self.assertEqual(kept[key], value)
        self.assertEqual(kept["resolution"]["by"], "installer_verification")
        self.assertTrue(all(v is True for v in kept["resolution"]["checks"].values()), kept["resolution"])
        self.assertEqual(self.executor.runs.status(rid)["state"], "needs_owner_intervention")   # the run history is untouched
        self.executor.challenge(self.good("0.1.0~dev5"), "approve")                                # and upgrades work again

    def test_a_record_is_not_released_while_any_check_fails_and_the_check_is_repeated_later(self):
        cfg = self.tmp / "installer.json"
        cfg.write_text('{"owner":"x"}')
        self.executor.upgrader.config_files = [str(cfg)]
        payload, go = self.attempt()
        go()
        rid = request_id(payload)[0]
        self.finish_with(payload, {"ok": False, "stopped": "health_check_failed", "rolled_back": False,
                                   "needs_owner_intervention": True, "changed_anything": True})
        self.executor.status(rid)
        cfg.write_text('{"owner":"CHANGED"}')
        self.assertEqual(len(self.executor.needs_attention()), 1)
        cfg.write_text('{"owner":"x"}')
        self.assertEqual(len(self.executor.needs_attention()), 1)            # rate limited: not re-checked at once
        self.executor._resolve_at = -1e9
        self.assertEqual(self.executor.needs_attention(), [])

    def test_other_kinds_of_attention_are_never_released_automatically(self):
        for stopped in ("restart_failed", "upgrade_worker_vanished_without_a_result", "dpkg_install_failed"):
            self.setUp()
            rid = self.failed_unrecovered(stopped=stopped)
            self.assertEqual(len(self.executor.needs_attention()), 1, stopped)
            self.assertTrue((self.tmp / ("broker/attention/%s.json" % rid)).exists())
        self.setUp()
        rid = self.failed_unrecovered(rolled_back=True)                      # claims a rollback: not this path's business
        self.assertEqual(len(self.executor.needs_attention()), 1)

    def test_after_the_installer_restarts_a_finished_upgrade_is_settled_not_blamed_on_the_restart(self):
        payload, go = self.attempt()
        go()
        rid = request_id(payload)[0]
        self.finish_with(payload, {"ok": True, "installed": "0.1.0~dev4", "to_version": "0.1.0~dev4",
                                   "from_version": "0.1.0~dev3", "changed_anything": True})
        self.executor._alive and os.close(self.executor._alive)          # the old installer process is gone
        self.build()
        self.assertEqual(self.executor.status(rid)["state"], "done")
        self.assertEqual(self.executor.needs_attention(), [])

    def test_a_worker_that_vanished_without_a_result_is_reported_honestly(self):
        payload, go = self.attempt()
        go()
        rid = request_id(payload)[0]
        job = self.executor.upgrader.job_dir(rid)
        data = json.loads((job / "job.json").read_text())
        data["started_at"] = int(time.time()) - 3600                      # long past the start-up grace period
        (job / "job.json").write_text(json.dumps(data))
        self.assertEqual(self.executor.status(rid)["state"], "needs_owner_intervention")
        self.assertEqual(self.executor.status(rid)["result"]["stopped"], "upgrade_worker_vanished_without_a_result")

    def test_an_ordinary_interrupted_install_still_needs_the_owner(self):
        self.executor.runs.consume(challenge=self.executor.runs.issue("c" * 64, "approve"), request_id="c" * 64,
                                   decision="approve", proof="p1", kind="install")
        self.executor._alive and os.close(self.executor._alive)
        self.build()
        self.assertEqual(self.executor.status("c" * 64)["state"], "needs_owner_intervention")


    # -- through the owner's approval flow ------------------------------------------------------------
    def flow(self, before_run=None):
        from stynpilot.approval import ApprovalFlow, pkce_challenge
        from stynpilot.requests import RequestStore
        from types import SimpleNamespace
        self.store = RequestStore(self.tmp / "state" / "requests.sqlite3")
        self.last = {}

        def exchange(code, verifier):
            assert pkce_challenge(verifier) == self.last["code_challenge"]
            now = int(time.time())
            return jwt.encode({"iss": ISS, "aud": APP, "sub": SUB, "iat": now, "exp": now + 300, "auth_time": now,
                               "nonce": self.last["nonce"]}, self.key, algorithm="RS256", headers={"kid": "k1"})
        flow = ApprovalFlow(store=self.store, broker=self.executor, exchange=exchange, before_run=before_run,
                            authorize={"endpoint": "https://issuer.example.test/authorize", "client_id": APP,
                                       "redirect_uri": "https://computer.example.test/approve/callback"})
        payload = self.good()
        receipt, _ = self.store.submit(kind="upgrade", software="stynpilot-self", device=DEVICE, owner=OWNER,
                                       proposer=SimpleNamespace(client="chatgpt-connector", name="chatgpt"),
                                       payload=payload, summary=["ask"], expires=time.time() + 3000)
        return flow, payload, receipt["request_id"]

    def approve_on_phone(self, flow, rid):
        shown = flow.page(rid)
        started = flow.choose(shown["view"], shown["csrf"], "approve")
        self.last = started["params"]
        return shown, flow.finish(started["params"]["state"], "auth0-code")

    def test_phone_approval_shows_the_root_summary_then_runs_in_the_background_and_settles_from_the_worker(self):
        flow, payload, rid = self.flow()
        shown, outcome = self.approve_on_phone(flow, rid)
        self.assertIn("0.1.0~dev4", " ".join(shown["summary"]))
        self.assertIn(payload["manifest"]["sha256"], " ".join(shown["summary"]))
        self.assertEqual((outcome["state"], outcome["ok"]), ("running", None))        # returns at once; worker continues
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "running")
        self.assertEqual(len(self.launched), 1)
        # the owner service restarts during the upgrade: on start it settles from the installer's own record
        self.assertEqual(flow.recover(patient=True), ([], [rid]))                      # still running: waits, never guesses
        self.finish_with(payload, {"ok": True, "installed": "0.1.0~dev4", "from_version": "0.1.0~dev3",
                                   "to_version": "0.1.0~dev4", "rolled_back": False, "changed_anything": True})
        self.assertEqual(flow.recover(patient=True), ([rid], []))
        status = self.store.status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual(status["state"], "done")
        self.assertEqual(status["result"]["to_version"], "0.1.0~dev4")

    def test_a_failed_and_rolled_back_upgrade_reaches_the_owner_as_failed_with_the_reason(self):
        flow, payload, rid = self.flow()
        self.approve_on_phone(flow, rid)
        self.finish_with(payload, {"ok": False, "stopped": "health_check_failed", "rolled_back": True,
                                   "changed_anything": True, "from_version": "0.1.0~dev3", "to_version": "0.1.0~dev4"})
        flow.recover(patient=True)
        status = self.store.status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual(status["state"], "failed")
        self.assertEqual((status["result"]["stopped"], status["result"]["rolled_back"]), ("health_check_failed", True))

    def test_the_owner_state_backup_runs_first_and_a_failure_stops_the_upgrade_before_anything_changes(self):
        seen = []
        flow, payload, rid = self.flow(before_run=lambda p, r: seen.append((p["kind"], r)))
        self.approve_on_phone(flow, rid)
        self.assertEqual(seen, [("upgrade", rid)])

    def test_failing_owner_backup_means_no_upgrade(self):
        def broken(payload, rid):
            raise OSError("disk full")
        flow, payload, rid = self.flow(before_run=broken)
        shown, outcome = self.approve_on_phone(flow, rid)
        self.assertEqual(outcome["state"], "failed")
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["result"]["stopped"], "owner_state_backup_failed")
        self.assertEqual(self.launched, [])

    def test_a_download_failure_after_approval_is_reported_as_nothing_changed(self):
        flow, payload, rid = self.flow()
        del self.downloads[release.download_url(payload["manifest"])]
        shown, outcome = self.approve_on_phone(flow, rid)
        self.assertEqual(outcome["state"], "failed")
        result = self.store.status(rid, owner=OWNER, device=DEVICE)["result"]
        self.assertIs(result["changed_anything"], False)
        self.assertEqual(self.launched, [])


class FakeSystem:
    """A simulated machine for the worker: package state, services, health, and switchable failures."""

    def __init__(self, installed, debs):
        self.version, self.debs = installed, debs
        self.fail_install, self.restart_fails, self.active, self.corrupt = set(), False, True, False
        self.doctor_code, self.log = 0, []

    def __call__(self, argv, timeout=120):
        self.log.append(list(argv))
        if argv[0] == "dpkg" and "-i" in argv:
            if argv[-1] in self.fail_install:
                if self.corrupt:
                    self.version = "BROKEN"                       # a half-installed package
                return 1, "dpkg: error"
            self.version = self.debs[argv[-1]]
            return 0, ""
        if argv[0] == "dpkg-query":
            return 0, self.version
        if argv[0] == "systemctl":
            if "restart" in argv:
                return (1, "failed") if self.restart_fails else (0, "")
            if "is-active" in argv:
                return 0, "active\n" if self.active else "inactive\n"
            return 0, ""
        if argv[0] == "doctor":
            return self.doctor_code, ""
        return 127, ""


class WorkerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.new, self.old = self.dir / "new.deb", self.dir / "previous.deb"
        self.new.write_bytes(b"new package")
        self.old.write_bytes(b"old package")
        self.config = self.dir / "installer.json"
        self.config.write_text('{"owner":"x"}')
        self.system = FakeSystem("0.1.0~dev3", {str(self.new): "0.1.0~dev4", str(self.old): "0.1.0~dev3"})
        self.clock = [0.0]

    def run_job(self, answers=True, endpoint_fn=None, **changes):
        job = {"job_dir": str(self.dir), "from_version": "0.1.0~dev3", "to_version": "0.1.0~dev4",
               "new_deb": str(self.new), "new_sha256": hashlib.sha256(self.new.read_bytes()).hexdigest(),
               "old_deb": str(self.old), "old_sha256": hashlib.sha256(self.old.read_bytes()).hexdigest(),
               "installer_unit": "stynpilot-installer.service", "owner_unit": "stynpilot-owner.service",
               "owner_user": "coty", "socket_path": "/run/x.sock", "restart_installer": True, "restart_owner": True,
               "config_hashes": {str(self.config): hashlib.sha256(self.config.read_bytes()).hexdigest()},
               "doctor_command": ["doctor"], "baseline_doctor_code": 0, "health_wait": 30, "settle_seconds": 0}
        job.update(changes)

        def tick():
            self.clock[0] += 1.0
            return self.clock[0]
        extra = {"endpoint": endpoint_fn} if endpoint_fn else {}
        worker = Worker(job, run=self.system, answers=answers if callable(answers) else (lambda p, *a: answers),
                        sleep=lambda s: None, monotonic=tick, **extra)
        return worker.execute()

    def installs(self):
        return [a[-1] for a in self.system.log if a[0] == "dpkg" and "-i" in a]

    def test_success_installs_restarts_checks_and_preserves_config(self):
        result = self.run_job()
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.system.version, "0.1.0~dev4")
        self.assertEqual(self.installs(), [str(self.new)])
        restarts = [a for a in self.system.log if "restart" in a]
        self.assertEqual(len(restarts), 2)
        self.assertTrue(any("--machine=coty@.host" in a for a in restarts))
        self.assertTrue(any(a[:2] == ["systemctl", "daemon-reload"] for a in self.system.log))

    def test_package_that_cannot_install_rolls_back_to_the_saved_previous_version(self):
        self.system.fail_install = {str(self.new)}
        result = self.run_job()
        self.assertEqual((result["ok"], result["stopped"], result["rolled_back"]), (False, "install_failed", True))
        self.assertEqual(self.system.version, "0.1.0~dev3")
        self.assertEqual(self.installs(), [str(self.new), str(self.old)])
        self.assertFalse(result["needs_owner_intervention"])

    def test_services_that_do_not_restart_trigger_rollback(self):
        self.system.restart_fails = True
        result = self.run_job(health_wait=5)
        self.assertEqual((result["ok"], result["stopped"]), (False, "restart_failed"))
        self.assertEqual(self.system.version, "0.1.0~dev3")

    def test_an_installer_that_never_answers_triggers_rollback(self):
        result = self.run_job(answers=lambda p, *a: self.system.version == "0.1.0~dev3", health_wait=6)   # only the OLD one answers
        self.assertEqual((result["ok"], result["stopped"], result["rolled_back"]), (False, "health_check_failed", True))
        self.assertEqual(self.system.version, "0.1.0~dev3")

    def test_doctor_problems_trigger_rollback_but_a_pre_existing_failure_is_not_blamed(self):
        self.system.doctor_code = 1
        result = self.run_job()
        self.assertEqual((result["ok"], result["stopped"]), (False, "health_check_failed"))
        self.system.version = "0.1.0~dev3"
        self.system.doctor_code = 1
        self.assertTrue(self.run_job(baseline_doctor_code=1)["ok"])

    def test_changed_configuration_triggers_rollback_and_is_reported(self):
        config, new = self.config, self.new

        class Changing(FakeSystem):
            def __call__(inner, argv, timeout=120):
                if argv[0] == "dpkg" and "-i" in argv and argv[-1] == str(new):
                    config.write_text('{"owner":"changed"}')
                return super().__call__(argv, timeout)
        self.system = Changing("0.1.0~dev3", {str(self.new): "0.1.0~dev4", str(self.old): "0.1.0~dev3"})
        result = self.run_job()
        self.assertEqual((result["ok"], result["stopped"]), (False, "health_check_failed"))
        self.assertTrue(any("configuration file changed" in n for n in result["notes"]))

    def test_if_the_rollback_also_fails_the_owner_is_told_plainly(self):
        self.system.fail_install = {str(self.new), str(self.old)}
        self.system.corrupt = True
        result = self.run_job(health_wait=5)
        self.assertFalse(result["ok"])
        self.assertFalse(result["rolled_back"])
        self.assertTrue(result["needs_owner_intervention"])

    def test_nothing_is_touched_if_the_packages_changed_on_disk_or_the_starting_version_moved(self):
        self.new.write_bytes(b"tampered")
        result = self.run_job(new_sha256=hashlib.sha256(b"new package").hexdigest())
        self.assertEqual((result["stopped"], result["changed_anything"]), ("new_package_changed_on_disk", False))
        self.new.write_bytes(b"new package")
        self.system.version = "0.1.0~dev9"
        result = self.run_job()
        self.assertEqual((result["stopped"], result["changed_anything"]),
                         ("installed_version_is_not_the_planned_starting_version", False))
        self.assertEqual(self.installs(), [])


if __name__ == "__main__":
    unittest.main()
