# Dev18: the first automated release

(Dev17 became a fix release, published by hand one last time: the first live build on the Ryzen found that the build sandbox hid
the system name resolver. Dev17 adds exactly one read-only file, /run/systemd/resolve/stub-resolv.conf, to the two network steps
(git fetch, wheel download) and records the failing step, exit code and output tail in the build record. Builds and tests stay
fully offline. Everything below applies to the first run that the Ryzen does by itself, now dev18.)

Dev18 is deliberately harmless: the only change from dev18 is the version number and this note. Its purpose is to prove, live on the
Ryzen, the whole path that dev16 built: build in the sandbox, review, ONE fingerprint approval, sign, publish, install, health check.

Nothing about dev18 is built, signed, staged or published by hand. The Ryzen does all of it.

## What the live run must show (check each)
1. Prepare: the installer fetches this exact commit, builds twice with identical SHA-256, runs the full test suite as the build account
   (real non-root run), and the package passes the upgrade inspection. Real systemd sandbox, tmpfs work area and wheel download work.
2. The approval summary shows commit, hash, size, test counts, key id fa3e08452ebb805d, and the reviewer note labelled unverified.
3. One fingerprint approval. Then: signed, draft created, three assets read back by content, made public, Git tag at the approved commit,
   upgrade installed with health check. No second prompt.
4. Status afterwards shows the release transaction `started` and the run finished `done`; the pinned package copy is gone.
5. Old trusted key 3ed773adf74d325e stays trusted until recovery and rotation are verified (not part of dev18).

## Not covered by dev18 (tracked)
Interrupted-release resume on the real machine, signing-key loss/rotation/revocation drills, stricter fetch-destination filtering,
manifest v2 multi-signature, signed revocation list. Reproducibility and the commit's own tests do not replace independent source review.
