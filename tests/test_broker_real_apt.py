"""Real Ubuntu end to end: approved install of htop with real apt/dpkg, then approved rollback.

Changes the machine it runs on, so it only runs as root on a DISPOSABLE Ubuntu machine with
STYNPILOT_REAL_APT_TEST=1. It never runs on the owner's computer by accident.
"""
import os
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REAL = os.environ.get("STYNPILOT_REAL_APT_TEST") == "1" and os.geteuid() == 0


@unittest.skipUnless(REAL, "set STYNPILOT_REAL_APT_TEST=1 and run as root on a disposable Ubuntu machine")
class RealAptTests(unittest.TestCase):
    def test_install_then_rollback_htop_for_real(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from stynpilot import catalog
        from stynpilot.broker import apt
        from stynpilot.broker.executor import Executor
        from stynpilot.broker.proof import ProofVerifier, approval_nonce
        from stynpilot.identity import account_id
        from stynpilot.requests import request_id

        self.assertIsNone(apt.installed_versions(["htop"])["htop"], "htop must not be installed before this test")
        iss, app, sub, device = "https://issuer.example.test/", "approval-app", "auth0|disposable", "dtdev_TESTONLYdisposable1"
        owner = account_id(verified_issuer=iss, verified_subject=sub)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        public.update(kid="k1", use="sig", alg="RS256")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        executor = Executor(state_dir=Path(tmp.name) / "broker", owner=owner, device=device,
                            verifier=ProofVerifier(issuer=iss, approval_client_id=app, jwks={"keys": [public]}))

        def proof(payload):
            rid, _ = request_id(payload)
            now = int(time.time())
            return jwt.encode({"iss": iss, "aud": app, "sub": sub, "iat": now, "exp": now + 300, "auth_time": now,
                               "nonce": approval_nonce(rid, rid)}, key, algorithm="RS256", headers={"kid": "k1"})

        plan, summary = catalog.install_plan("htop", owner=owner, device=device, resolve_apt=apt.resolve)
        payload = plan.content()
        print("\nPlan the owner would approve:\n  " + "\n  ".join(summary))
        result = executor.install(payload, proof(payload), software="htop")
        print("Install result:", result)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["rollback_verified"])
        out = subprocess.run(["dpkg-query", "-W", "-f", "${Version}", "htop"], capture_output=True, text=True)
        self.assertEqual(out.stdout, next(p["version"] for p in payload["steps"][0]["packages"] if p["name"] == "htop"))

        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        back = {"kind": "rollback", "software": "htop", "rollback_id": result["rollback_id"], "request_id": request_id(payload)[0],
                "snapshot_id": result["rollback_id"], "owner": owner, "device": device, "expires_at": expires}
        undone = executor.rollback(back, proof(back))
        print("Rollback result:", undone)
        self.assertTrue(undone["ok"], undone)
        for name in [p["name"] for p in payload["steps"][0]["packages"]]:
            self.assertIsNone(apt.installed_versions([name])[name], name)


if __name__ == "__main__":
    unittest.main()
