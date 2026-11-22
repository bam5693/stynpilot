"""Install-plan validation. Offline: no root, network, Docker, apt or AI usage.

ChatGPT's original 15 tests (GitLab commit 0e81d7b1), plus tests for the review fixes.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from stynpilot.plan import PlanError, validate_plan

NOW = datetime(2026, 11, 21, 12, tzinfo=timezone.utc)
DIGEST = "a" * 64


def stamp(delta_minutes):
    return (NOW + timedelta(minutes=delta_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def plan():
    return {
        "schema": 1,
        "owner": "test-owner",
        "device": "test-device",
        "expires_at": stamp(15),
        "backup": "required-before-mutation",
        "rollback": "restore-verified-snapshot",
        "steps": [{"kind": "container", "app": "jellyfin", "image": "ghcr.io/example/jellyfin@sha256:" + DIGEST,
                   "bind_ip": "100.101.102.103", "host_port": 8096, "container_port": 8096, "data_subdir": "jellyfin"}],
    }


def validate(p):
    return validate_plan(p, expected_owner="test-owner", expected_device="test-device", now=NOW)


class PlanTests(unittest.TestCase):
    def refused(self, p):
        with self.assertRaises(PlanError):
            validate(p)

    def test_stable_digest_independent_of_field_order(self):
        original = plan()
        reordered = dict(reversed(list(original.items())))
        self.assertEqual(validate(original).plan_sha256, validate(reordered).plan_sha256)
        self.assertEqual(len(validate(original).plan_sha256), 64)

    def test_different_action_changes_digest(self):
        other = plan()
        other["steps"][0]["host_port"] = 9000
        self.assertNotEqual(validate(plan()).plan_sha256, validate(other).plan_sha256)

    def test_wrong_identity_fails(self):
        for key in ("device", "owner"):
            p = plan()
            p[key] = "attacker"
            with self.subTest(key=key):
                self.refused(p)

    def test_untrusted_context_values_are_refused(self):
        for owner in ("", None, "x" * 200, "has space"):
            with self.subTest(owner=owner), self.assertRaises(PlanError):
                validate_plan(plan(), expected_owner=owner, expected_device="test-device", now=NOW)

    def test_raw_command_refused(self):
        p = plan()
        p["steps"] = [{"kind": "shell", "command": "curl bad | bash"}]
        self.refused(p)

    def test_docker_privilege_escape_refused(self):
        for key, value in (("privileged", True), ("network_mode", "host"), ("volumes", ["/run/docker.sock:/run/docker.sock"]),
                           ("cap_add", ["SYS_ADMIN"]), ("user", "root"), ("devices", ["/dev/sda"]), ("pid", "host")):
            p = plan()
            p["steps"][0][key] = value
            with self.subTest(key=key):
                self.refused(p)

    def test_public_and_wildcard_bind_refused(self):
        for ip in ("0.0.0.0", "::", "8.8.8.8", "2001:4860:4860::8888", "::ffff:192.168.1.5", "224.0.0.1", "lan"):
            p = plan()
            p["steps"][0]["bind_ip"] = ip
            with self.subTest(ip=ip):
                self.refused(p)

    def test_lan_tailscale_and_loopback_binds_allowed(self):
        for ip in ("192.168.1.20", "10.0.0.5", "100.101.102.103", "127.0.0.1", "::1"):
            p = plan()
            p["steps"][0]["bind_ip"] = ip
            self.assertEqual(validate(p).step_count, 1)

    def test_host_path_escape_refused(self):
        for path in ("../secrets", "/", "/etc", "../../owner", "another-app"):
            p = plan()
            p["steps"][0]["data_subdir"] = path
            with self.subTest(path=path):
                self.refused(p)

    def test_unpinned_image_refused(self):
        p = plan()
        p["steps"][0]["image"] = "jellyfin:latest"
        self.refused(p)

    def test_unversioned_apt_refused(self):
        p = plan()
        p["steps"] = [{"kind": "apt", "packages": [{"name": "git"}]}]
        self.refused(p)

    def test_versioned_apt_allowed(self):
        p = plan()
        p["steps"] = [{"kind": "apt", "packages": [{"name": "git", "version": "1:2.47.3-0ubuntu1"}]}]
        self.assertEqual(validate(p).step_count, 1)

    def test_same_package_twice_in_a_plan_refused_even_across_steps(self):
        p = plan()
        pkg = {"name": "git", "version": "1:2.47.3-0ubuntu1"}
        p["steps"] = [{"kind": "apt", "packages": [pkg, dict(pkg)]}]
        self.refused(p)
        p["steps"] = [{"kind": "apt", "packages": [pkg]}, {"kind": "apt", "packages": [dict(pkg, version="2")]}]
        self.refused(p)

    def test_apt_step_with_container_fields_refused(self):
        p = plan()
        p["steps"] = [{"kind": "apt", "packages": [{"name": "git", "version": "1"}], "image": "x@sha256:" + DIGEST}]
        self.refused(p)

    def test_duplicate_app_or_bind_refused(self):
        p = plan()
        p["steps"].append(deepcopy(p["steps"][0]))
        self.refused(p)
        p = plan()
        second = dict(p["steps"][0], app="other", data_subdir="other")
        p["steps"].append(second)
        self.refused(p)  # same address and port

    def test_missing_backup_refused(self):
        p = plan()
        p["backup"] = "none"
        self.refused(p)

    def test_expired_and_excessively_long_plans_refused(self):
        for delta in (-5, 0, 60 * 24 + 1):
            p = plan()
            p["expires_at"] = stamp(delta)
            with self.subTest(delta=delta):
                self.refused(p)

    def test_only_one_expiry_spelling_is_accepted(self):
        for text in ("2026-11-21T12:15:00+00:00", "2026-11-21T12:15:00.000Z", "2026-11-21 12:15:00Z", "tomorrow"):
            p = plan()
            p["expires_at"] = text
            with self.subTest(text=text):
                self.refused(p)

    def test_unknown_fields_refused(self):
        p = plan()
        p["unreviewed_shell"] = True
        self.refused(p)

    def test_no_bool_as_port_or_schema(self):
        p = plan()
        p["steps"][0]["host_port"] = True
        self.refused(p)
        p = plan()
        p["schema"] = True
        self.refused(p)

    def test_validated_content_cannot_be_changed_by_mutating_the_input(self):
        p = plan()
        result = validate(p)
        p["steps"][0]["bind_ip"] = "0.0.0.0"
        p["steps"].append({"kind": "shell", "command": "rm -rf /"})
        content = result.content()
        self.assertEqual(content["steps"][0]["bind_ip"], "100.101.102.103")
        self.assertEqual(len(content["steps"]), 1)
        content["steps"].clear()  # a copy: the stored plan is untouched
        self.assertEqual(len(result.content()["steps"]), 1)


if __name__ == "__main__":
    unittest.main()
