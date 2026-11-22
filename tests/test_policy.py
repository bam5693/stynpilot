"""GREEN / YELLOW / BLACK policy: fail closed, BLACK wins, tables cannot overlap."""
import unittest
from types import MappingProxyType

from stynpilot import policy
from stynpilot.policy import BLACK_TIER, GREEN_TIER, YELLOW_TIER, classify, explain, validate_tables


class PolicyTests(unittest.TestCase):
    def test_green_yellow_and_default_deny(self):
        self.assertEqual(classify("development.test", "stynpilot-dev"), GREEN_TIER)
        self.assertEqual(classify("software.install", "ryzen-software"), YELLOW_TIER)
        self.assertEqual(classify("software.install", "anything-else"), BLACK_TIER)
        self.assertEqual(explain("made.up", "ryzen")["reason"], "default_deny")

    def test_owner_four_rules_always_need_his_approval(self):
        for op, res in (("owner.publish_as", "public-post"), ("money.spend", "purchase"),
                        ("money.spend", "subscription"), ("account.signup", "external-service"),
                        ("private_data.access", "owner-private-files")):
            self.assertEqual(classify(op, res), YELLOW_TIER, (op, res))

    def test_black_always_wins(self):
        self.assertEqual(explain("shell.exec", "stynpilot-dev")["reason"], "black_operation")
        self.assertEqual(explain("backup.inspect", "existing-backups")["reason"], "black_resource")
        self.assertEqual(classify("approval.self_grant", "ryzen"), BLACK_TIER)

    def test_bad_types_fail_closed(self):
        for op, res in ((None, "ryzen"), ("device.health", None), (1, 2), (b"device.health", "ryzen")):
            self.assertEqual(explain(op, res), {"tier": BLACK_TIER, "reason": "invalid_type"})

    def test_tables_are_read_only(self):
        self.assertIsInstance(policy.GREEN, MappingProxyType)
        self.assertIsInstance(policy.YELLOW, MappingProxyType)
        with self.assertRaises(TypeError):
            policy.GREEN["ryzen"] = frozenset(("shell.exec",))

    def test_overlapping_or_malformed_tables_are_refused(self):
        ok = ({"r": frozenset(("op.a",))}, {"op.b": frozenset(("r2",))}, frozenset(("op.c",)), frozenset(("bad",)))
        validate_tables(*ok)
        for bad in (
            ({"r": frozenset(("op.a",))}, {"op.a": frozenset(("r2",))}, frozenset(), frozenset()),   # GREEN and YELLOW
            ({"r": frozenset(("op.a",))}, {}, frozenset(("op.a",)), frozenset()),                    # GREEN op is BLACK
            ({}, {"op.b": frozenset(("bad",))}, frozenset(), frozenset(("bad",))),                    # YELLOW res is BLACK
            ({"R": frozenset(("op.a",))}, {}, frozenset(), frozenset()),                             # not lowercase
        ):
            with self.assertRaises(ValueError):
                validate_tables(*bad)

    def test_tier_table_lists_everything(self):
        table = policy.tier_table()
        self.assertEqual(table[BLACK_TIER]["default"], "deny")
        self.assertIn("money.spend", dict(table[YELLOW_TIER]))


if __name__ == "__main__":
    unittest.main()
