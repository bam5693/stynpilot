"""The owner's decision proof: an Auth0-signed ID token bound to ONE root-issued challenge.

What this proves, precisely (and what it does not):
- The root installer issues a random, single-use **challenge** for one request and one
  decision ("approve" or "deny"), and renders the plain-English summary of the exact plan
  itself (``render_summary``). The approval page (G5) must show that root-rendered text.
- The owner then signs in to his Auth0 tenant with
  ``nonce = decision_nonce(decision, request_id, plan_sha256, challenge)``. Auth0 signs an
  ID token carrying that nonce.
- The installer accepts the token only if it's signed by the trusted Auth0 keys, for the
  approval app, for the owner's account, with a sign-in under 5 minutes old, and its
  nonce matches a challenge the installer issued, unexpired and unused, for this exact
  request, plan and decision.

So a token proves that the owner freshly authenticated *for this specific decision on
this specific plan*, through a flow the installer started. It does NOT by itself prove
what the owner's screen showed. That depends on the G5 page displaying the
root-rendered summary from a component the AI-facing service can't alter. G5 must meet
that requirement (see MASTER_PLAN G5). A generic Auth0 sign-in, a sign-in without a
root-issued challenge, or a replayed one is never accepted.

Needs PyJWT with cryptography (Ubuntu: python3-jwt, python3-cryptography).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time

import jwt

from ..identity import account_id

_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
DECISIONS = ("approve", "deny")
MAX_AUTH_AGE = 300            # seconds between the owner's sign-in and the decision
MAX_TOKEN_BYTES = 8192


class ProofDenied(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def decision_nonce(decision, request_id, plan_sha256, challenge):
    if decision not in DECISIONS:
        raise ProofDenied("invalid_decision")
    for value in (request_id, plan_sha256, challenge):
        if type(value) is not str or not _HEX64.fullmatch(value):
            raise ProofDenied("invalid_request")
    text = "stynpilot-decision-v2|%s|%s|%s|%s" % (decision, request_id, plan_sha256, challenge)
    return hashlib.sha256(text.encode()).hexdigest()


def summary_hash(lines):
    """Fingerprint of the root-rendered summary, so a relay that alters the text is detected."""
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def proof_fingerprint(id_token):
    return hashlib.sha256(id_token.encode("ascii", "replace")).hexdigest()


def render_summary(payload):
    """Plain-English text of an install or rollback payload, produced by the root installer itself."""
    if payload.get("kind") == "release":
        i = payload.get("intent") or {}
        lines = ["Publish and install a new StyNpilot release, version %s, in ONE approval." % str(i.get("version")),
                 "Built from source commit %s. StyNpilot built it twice on this computer and got the identical package (SHA-256 %s, %s bytes)."
                 % (str(i.get("commit"))[:12], str(i.get("sha256")), str(i.get("size"))),
                 "Test suite on that commit: %s passed, %s failed, %s skipped."
                 % (i.get("tests_passed"), i.get("tests_failed"), i.get("tests_skipped")),
                 "If you approve: this computer signs the release with its own release key (%s), publishes it to the StyNpilot project's "
                 "GitHub releases, then upgrades itself, restarts, checks it works, and automatically puts the current version back if it does not."
                 % str(i.get("key_id")),
                 "Nothing is signed or published before you approve. The signing key and the GitHub access never leave this computer.",
                 "This replaces only StyNpilot's own program files. Your settings, approvals and sign-in setup are not touched."]
        if i.get("review_note"):
            lines.append("Reviewer note (written by an assistant, not verified by StyNpilot): %s" % str(i["review_note"]))
        lines.append("Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z"))
        return lines
    if payload.get("kind") == "passkey":
        expires = "Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z")
        if payload.get("action") == "enroll":
            return ["Add a passkey named \"%s\" for approving StyNpilot changes." % str(payload.get("label")),
                    "After you approve this, your phone is asked to create the passkey. It must be created within 3 minutes, on this "
                    "page's address only, and it can do nothing until you approve a second, final step that names that exact key.",
                    "If your phone syncs passkeys through your Google account, this one can also be used from any device signed in "
                    "to that account. Adding a passkey always asks for your Auth0 sign-in, never an existing passkey. A passkey that stays on one device is safer; StyNpilot shows which kind each one is.",
                    expires]
        if payload.get("action") == "activate":
            return ["Activate the new passkey \"%s\" (short ID %s, key fingerprint %s)." % (
                        str(payload.get("label")), str(payload.get("kid")), str(payload.get("pub"))[:16]),
                    "Until you approve this, that passkey can approve nothing. Your sign-in here commits to this exact key: no "
                    "other key can be activated by it. After this, the passkey can approve StyNpilot changes whenever your phone "
                    "confirms it is you (fingerprint, face or screen lock; the phone decides which).",
                    "Approve only if you just created this passkey yourself. If you did not, deny it.", expires]
        return ["Remove the passkey with short ID %s." % str(payload.get("kid")),
                "It can no longer approve anything. Other passkeys and your Auth0 sign-in keep working.", expires]
    if payload.get("kind") == "backup" and payload.get("action") == "rotate_key":
        expires = "Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z")
        where = "the root installer side" if payload.get("side") == "root" else "your own side"
        if payload.get("mode") == "lost_key":
            return ["Start a NEW encryption key for StyNpilot's backups on %s, because the old key is missing." % where,
                    "Backups that needed the missing key can no longer be opened by StyNpilot. They are moved to a separate "
                    "'unreadable' folder and kept; nothing is deleted. Backups made with an older key that is still present stay "
                    "where they are and stay usable.",
                    "Approve only if you know the key is really gone (for example after a disk problem).", expires]
        if payload.get("mode") == "fresh_key":
            return ["Start a NEW encryption key for NEW backups on %s, because the record of the old key's one-time values is "
                    "missing or unreliable." % where,
                    "Existing backups are not changed: they stay readable with the old key, which is kept and never used to "
                    "encrypt anything again. Nothing is restored or deleted.", expires]
        return ["Replace the encryption key of StyNpilot's backups on %s with a new key." % where,
                "Every backup is re-encrypted with the new key and checked before it replaces the old copy. If anything is "
                "interrupted (even a power cut), it carries on safely from where it stopped. The old key is KEPT (not destroyed); "
                "nothing is restored or deleted.", expires]
    if payload.get("kind") == "backup":
        expires = "Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z")
        return ["Change how many encrypted backups StyNpilot keeps: %s daily and %s weekly (for the root installer side and "
                "your own side)." % (payload.get("daily"), payload.get("weekly")),
                "On the root installer side, older backups beyond that are deleted when new ones are made. On your own side, "
                "automatic deletion is temporarily turned off, so all of your side's backups are kept for now. Whatever this says, "
                "the newest complete, verified backup is always kept, and backups that failed a check are kept for inspection.",
                "Nothing is backed up, restored or deleted right now by this approval.", expires]
    if payload.get("kind") == "runner":
        expires = "Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z")
        name = str(payload.get("name"))
        if payload.get("action") == "setup":
            return ["Set up the sandboxed command runner (one time).",
                    "This creates a locked-down system account named stynpilot-run (no login, no sudo, no network, no groups) "
                    "and a folder called StyNpilot-Projects in your home folder. It authorizes no project and runs nothing by itself.",
                    "StyNpilot then runs a built-in self-test that tries to break out of the sandbox. Assistants cannot run any "
                    "command until that test passes.", expires]
        if payload.get("action") == "enroll":
            return ["Authorize the project folder StyNpilot-Projects/%s for assistant work." % name,
                    "Assistants may read and edit files in that folder, and run a short fixed list of approved commands there "
                    "(tests, builds, git status/diff/log) inside the sandbox as the locked-down account: no network, no view of "
                    "your other files, passwords or StyNpilot's own data. The folder is created if it does not exist.",
                    "You can remove this authorization at any time.", expires]
        return ["Remove the authorization for StyNpilot-Projects/%s." % name,
                "Assistants will no longer be able to edit or run commands there. Your files are not deleted.", expires]
    if payload.get("kind") == "rollback":
        return ["Roll back %s (install %s)." % (payload.get("software"), str(payload.get("rollback_id"))[:12]),
                "Packages that install added are removed (their settings files are kept); packages it "
                "upgraded go back to their saved earlier versions. Application data and other changes are not restored.",
                "Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z")]
    lines = ["Install %s on device ending ...%s." % (payload.get("software"), str(payload.get("device"))[-4:])]
    generic = str(payload.get("software", "")).startswith("apt-")
    asked = {n for step in payload.get("steps", []) for n in step.get("requested", [])}
    for step in payload.get("steps", []):
        for package in step.get("packages", []):
            role = ""
            if generic:
                role = "asked for by the assistant" if package["name"] in asked else "needed by it"
            lines.append("Package %s, exact version %s, from the Ubuntu archive%s." % (
                package["name"], package["version"], " (%s)" % role if role else ""))
    if generic:
        lines.append("The assistant chose these package names; StyNpilot checked them against the signed Ubuntu archive "
                     "and refuses kernels, boot, login, firewall and other core packages. Package install scripts run as "
                     "root: a signed source shows where a package came from, not that it is harmless.")
    lines.append("Backup limits: this saves the packages it changes and their tracked settings files so they can be "
                 "rolled back. It is not a full system snapshot: application data and other changes are not restored.")
    lines.append("Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z"))
    return lines


class ProofVerifier:
    def __init__(self, *, issuer, approval_client_id, jwks, clock=time.time, jwks_loader=None, refresh_cooldown=30.0,
                 monotonic=time.monotonic):
        """``jwks_loader``: optional callable returning the issuer's CURRENT JWKS (fetched from the pinned issuer
        origin). It is consulted only when a token names a key ID we don't have (a provider key rotation), at
        most once per ``refresh_cooldown`` seconds, and the new set goes through the same strict key checks.
        A failed refresh keeps the old keys. Issuer, audience, RS256 only and owner checks never change."""
        from ..server.tokens import _load_keys        # same strict JWKS rules as the endpoint
        if not isinstance(issuer, str) or not issuer.startswith("https://"):
            raise ValueError("HTTPS issuer required")
        if type(approval_client_id) is not str or not approval_client_id:
            raise ValueError("Approval app client ID required")
        self.issuer, self.client_id, self.clock = issuer, approval_client_id, clock
        self._load_keys, self._loader, self._monotonic = _load_keys, jwks_loader, monotonic
        self._cooldown, self._last_refresh, self._lock = float(refresh_cooldown), None, threading.Lock()
        self.keys = _load_keys(jwks)

    def _key_for(self, kid):
        key = self.keys.get(kid)
        if key is not None or self._loader is None or type(kid) is not str:
            return key
        with self._lock:
            now = self._monotonic()
            if self._last_refresh is None or now - self._last_refresh >= self._cooldown:
                self._last_refresh = now
                try:
                    self.keys = self._load_keys(self._loader())      # replaced whole, or not at all
                except Exception:
                    pass
            return self.keys.get(kid)

    def verify(self, id_token, *, expected_nonce, owner):
        """Return the proof fingerprint if this token carries exactly ``expected_nonce`` for the owner."""
        if type(id_token) is not str or not 20 <= len(id_token) <= MAX_TOKEN_BYTES:
            raise ProofDenied("proof_missing")
        try:
            header = jwt.get_unverified_header(id_token)
            if header.get("alg") != "RS256" or "jku" in header or "x5u" in header:
                raise ProofDenied("proof_invalid")
            key = self._key_for(header.get("kid"))
            if key is None:
                raise ProofDenied("proof_invalid")
            claims = jwt.decode(id_token, key=key, algorithms=["RS256"], issuer=self.issuer,
                                audience=self.client_id, leeway=5,
                                options={"require": ["iss", "aud", "exp", "iat", "sub", "nonce", "auth_time"]})
        except ProofDenied:
            raise
        except (jwt.PyJWTError, TypeError, ValueError):
            raise ProofDenied("proof_invalid") from None
        if not hmac.compare_digest(str(claims.get("nonce")), expected_nonce):
            raise ProofDenied("proof_is_for_a_different_decision")
        auth_time = claims.get("auth_time")
        if type(auth_time) is not int or not 0 <= self.clock() - auth_time <= MAX_AUTH_AGE:
            raise ProofDenied("owner_sign_in_not_recent")
        try:
            who = account_id(verified_issuer=self.issuer, verified_subject=claims["sub"])
        except ValueError:
            raise ProofDenied("proof_invalid") from None
        if not hmac.compare_digest(who, owner):
            raise ProofDenied("proof_is_not_from_the_owner")
        return proof_fingerprint(id_token)
