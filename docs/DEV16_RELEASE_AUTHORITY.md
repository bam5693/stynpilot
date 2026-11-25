# Dev16: Release Authority (one approval = build verified, sign, publish, install)

Goal: no more Work mode or hand-published releases. An assistant proposes a commit; the Ryzen builds and tests it; the owner taps ONE
approval (passkey); the Ryzen signs, publishes to GitHub and upgrades itself with health checks and automatic rollback.

## Flow
1. `commander_prepare_stynpilot_release(device, commit, version)` (GREEN, changes nothing): the installer fetches that exact 40-char commit
   of the public repo and, as an unprivileged account (`setpriv`, no new privileges), builds the .deb TWICE (umask 022 and 077, different
   folders) and requires identical SHA-256, runs the whole test suite and requires zero failures. Root re-reads and re-hashes the result.
2. `stynpilot_release_status(device, commit)` (read-only): building / ready / failed (+why), hash, size, test counts.
3. `commander_request_stynpilot_release(device, commit, version, review_note)`: files a YELLOW `release` request. The payload's `intent`
   is derived by the installer from its own record; a payload that differs in any field is refused. The owner sees commit, hash, test
   counts, key id, what happens on approval, and the review note labelled as an unverified assistant note.
4. Owner approves once (passkey or Auth0). Only then the installer: verifies the proof, backs up its records, builds the manifest,
   signs it with its own key, uploads package+manifest+signature to the GitHub release for that tag (created at that exact commit; a tag on
   a different commit is refused; re-running is safe), re-downloads it through the normal signed-release path, runs the existing protected
   upgrade (package inspection, rollback copy, worker, health check, automatic rollback). Everything that can fail runs BEFORE the
   approval is consumed; a failure leaves the approval unspent.

## Who holds what
- Signing key: generated on the Ryzen at the console (`release/signing-ed25519.pem`, root, 0600). Never exported; no assistant sees it.
- GitHub token: entered once at the console with hidden input, root 0600, used only against api/uploads.github.com (no redirects followed).
- Trust: the machine trusts package keys plus a console-written addendum `/var/lib/stynpilot/trusted-release-keys.json` (keys + revoked).
- Nothing is signed or published before approval; a wrong/replayed/other-request proof publishes nothing (tested).

## Honest limits
- Root on the Ryzen can do anything a root-owned key allows; this protects against assistants and the owner-side service, not a root compromise.
- "Independent review" is NOT enforced by code: the reviewer note is a labelled, unverified assistant statement. What IS enforced: exact
  commit, reproducible build, green tests (run by the machine), one owner proof.
- The tests run on the builder account from the pinned commit's own test suite (a malicious commit could weaken its tests; the owner/review
  is the control for that, which is why the summary shows commit and counts).
- Not in this slice: manifest v2 multi-signature, signed revocation list/anti-rollback beyond "newer than installed". The old sandbox key stays
  trusted until the owner revokes it via the addendum.

## Turning it on (owner, at the Ryzen console, after dev16 is installed)
1. Create a fine-grained GitHub token: repository bam5693/stynpilot only, permission Contents: Read and write, short expiry.
2. `sudo useradd --system --no-create-home --shell /usr/sbin/nologin stynpilot-build`; `sudo install -d -m 0755 /var/lib/stynpilot-build`
3. `echo '{"build_user":"stynpilot-build"}' | sudo tee /etc/stynpilot/release.json; sudo chmod 600 /etc/stynpilot/release.json`
4. Restart the installer, then `sudo stynpilot service release --config /etc/stynpilot/installer.json --action init` (creates the key, trusts it)
5. `... --action set-token` (paste token), then `... --action status`.
No installer.json change (dev14 rollback still parses it; dev14 ignores release.json).
Dev16 itself is published the old way one last time; the first automated release is dev17 (harmless test release).
