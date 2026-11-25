# Dev16: Release Authority (one approval = build verified, sign, publish, install)

Goal: no more Work mode or hand-published releases. An assistant proposes a commit; the Ryzen builds and tests it; the owner taps ONE
approval (passkey); the Ryzen signs, publishes to GitHub and upgrades itself with health checks and automatic rollback.

## Flow
1. `commander_prepare_stynpilot_release(device, commit, version)` (GREEN, changes nothing). One build at a time machine-wide (lock), the newest
   3 builds kept. Every step runs as the unprivileged build account inside the same systemd-run sandbox the owner's project jobs use
   (no privileges, read-only system, installer folders hidden, memory/process/CPU/time limits, own /tmp), in a size-limited memory-backed
   work area. Network exists ONLY for two steps: `git fetch` of that exact commit (hooks off) and `pip download` of exactly the wheels the
   commit's `vendor.lock` names (the build re-checks each SHA-256). Building and testing have no network. A step that times out is stopped
   with everything it started. The package is built TWICE (umask 022 and 077); root reads BOTH outputs itself (directory handles, no links,
   exactly one file, size limit enforced while reading), hashes each, and requires them equal. The test suite runs directly and BOTH its exit
   status and summary must be clean. The package must pass the upgrade path's own inspection before it can ever be offered.
2. `stynpilot_release_status(device, commit)` (read-only).
3. `commander_request_stynpilot_release(...)`: YELLOW `release` request; `intent` is derived by the installer, any difference is refused. The
   reviewer note is shown labelled as an unverified assistant note.
4. Owner approves once. The installer then, in this order: checks the proof; checks the challenge is issued, fresh, unused and for this
   decision; does the checks that need no external effect (GitHub token works, the tag is free or already at the approved commit, package intact
   and acceptable, records backed up); **reserves the approval durably** (challenge used, run recorded, passkey counter/audit written); and only
   then runs a recorded transaction: signed -> drafted -> uploaded (each file read back and compared by content) -> published (draft made
   public, the real Git tag resolved and required to equal the approved commit) -> upgrade started. Every state is written to disk before the
   next step.
5. If anything stops after the reservation, the reply says so: `release_approval_spent_stopped_after_<state>_resumable_yes|no_<reason>`. It never
   says "unchanged" or "unspent". `commander_resume_stynpilot_release(device, request_id)` continues only that exact transaction (the intent is
   re-derived and must still match the verified build; no new authority; within 24 hours, then it is closed as abandoned and a new approval is
   needed). A restart of the installer leaves a pending release alone (it is not damage); status shows `release: {state, approval_spent, resumable}`.

## Who holds what
- Signing key: generated on the Ryzen at the console (`release/signing-ed25519.pem`, root, 0600). Never exported; no assistant sees it.
- GitHub token: entered once at the console with hidden input, root 0600, used only against api/uploads.github.com (no redirects followed).
- Trust: read fresh on every use (a console-added or revoked key counts immediately); the machine trusts package keys plus a console-written addendum `/var/lib/stynpilot/trusted-release-keys.json` (keys + revoked).
- `service release --action init` never un-revokes a key (it refuses) and re-reads trust after writing to prove it took effect.
- Nothing is signed or published before approval; a wrong/replayed/other-request proof publishes nothing (tested).

## Honest limits
- The sandbox and memory-backed work area (`mount -t tmpfs`) are only exercised for real on the Ryzen: if the machine refuses either, the build FAILS CLOSED
  (`work_area_unavailable` or a failed step). Expect to find and fix any such environment detail in the dev17 test release.
- The fetch/wheel steps have open internet (systemd cannot restrict to GitHub/PyPI names); they run no code from the commit with network and hold no secrets.
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
