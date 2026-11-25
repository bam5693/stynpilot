# dev15: passkey approvals (Phase R, step 1)

One tap, one fingerprint or PIN, and the installer itself checks it. Auth0 stays as enrollment and recovery.

## What changed
* `webauthn.py`: strict WebAuthn verifier. ES256 only, attestation "none" only, exact origin and relying-party ID, user
  verification required on EVERY assertion, extensions and cross-origin refused, tiny bounded CBOR reader.
* `broker/passkeys.py`: root-only passkey store (`<state>/passkeys.sqlite3`, 0600) with a hash-chained audit log, enrollment
  windows, revocation, counter check, and `retirement_ready()` (>= 2 active passkeys).
* `broker/executor.py`: ONE owner-proof gate (`_prove`). A proof is either an Auth0 token (as before) or a JSON passkey assertion.
  The WebAuthn challenge IS the decision nonce `sha256("stynpilot-decision-v2|decision|request|plan|root challenge")`, so an
  approval is bound to the exact action, device, parameters, decision and a single-use root challenge. `install`, `rollback`,
  `upgrade`, `runner_admin`, `passkey_admin` and `deny` all use it (a test fails if any path bypasses it).
* New YELLOW request kind `passkey` (enroll, revoke). Enrollment opens a 3-minute single-use window; the phone creates the key
  inside it, in the browser that approved.
* Approval page: one "Approve with fingerprint or PIN" button (needs a tap; the prompt is immediate, no Auth0 login). Auth0 is
  under "Use the Auth0 sign-in instead". A read-only pre-check means a wrong finger or cancelled prompt changes nothing.
* Assistant tools: `commander_request_passkey_enrollment`, `commander_request_passkey_revocation`, `passkey_status`.
  Assistants can ask and read public facts; they never receive a challenge, a credential or a key.

## Config (installer, optional; absent = passkeys off and nothing changes)
`"passkey_rp_id": "deckplayhq.tail4bc147.ts.net", "passkey_origin": "https://deckplayhq.tail4bc147.ts.net:8443"`.
Adding these two keys to the root installer config is a live change and needs the owner's approval; this release does not make it.

## Honest limits
1. A passkey proves "the holder of this passkey, unlocked by fingerprint or PIN, signed THIS challenge on THIS origin". It does
   not prove what the screen displayed (WebAuthn has no transaction display here). The text comes from the root installer.
2. Registration uses attestation "none": the installer cannot tell which device made a key. Protection = only an owner-approved
   request opens the window, 3 minutes, one challenge delivered only to the approving browser (cookie-bound). A compromised
   owner-side service holding the open window could substitute its own key. Auth0 recovery and revocation remain.
3. Synced passkeys (backup state set) are accepted and flagged on the page and in `passkey_status`.
4. Signature counter: 0/0 is accepted (synced passkeys); a counter that goes backwards is refused.
5. A native in-chat biometric button is not provided: chat widgets run in sandboxes that cannot use a passkey bound to this
   origin. The assistant gives the approval link; one tap + fingerprint. The installer's check is unchanged if that arrives later.
6. After an owner-service restart between approval and key creation the browser binding is lost; the owner asks again.
7. The old Ed25519 release key is NOT retired by dev15 (dev16/17).

## Review focus
`_prove` / `_verify_passkey` / `passkey_precheck`; challenge construction; `PasskeyStore.complete`/`_window`; cookie/session binding in
`ApprovalFlow.enroll_page`; CSP and JSON endpoints in `approval_web.py`; the `_check_payload` ordering for `passkey` (revocation must
work while the installer needs attention); audit chain; `read_private_json` optional keys.
