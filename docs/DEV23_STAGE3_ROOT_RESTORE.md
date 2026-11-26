# Dev23 Stage 3 installer-side restoration

The package target is `0.1.0~dev25`. An enrolled proposer can file `commander_request_root_restore` for a named installer archive. The installer authenticates the archive, checks completeness and renders the owner decision. The signed request includes the encrypted file's SHA-256, creation time, version, restoration scope, changed settings filenames, current security-state digest, next restore generation, owner, device and expiry. Approval uses a single-use root challenge and a verified owner passkey.

## Scope and admission

The restore recovers install ledger entries, snapshots and unresolved attention records. It combines current and recovered records, preserves rollback tombstones and refuses conflicting contents. Settings stay in place. The worker shows differences during approval. Owner records, the root vault, keys, nonce history and release transaction files remain outside the replacement set.

The installer requires an idle runner, an idle installer, a usable archive, the packaged recovery path unit and the enrolled service configuration. The owner flow checks for owner key rotation. The approving socket call takes exclusive admission while regular operations use shared admission. The root operation and vault locks guard the final fingerprint and security check. A durable intent closes the runner and mutation gates before the approval spend. An intent without its matching spent proof cannot initiate work.

## Recovery and rollback

A package-owned systemd path activates an independent worker when a pending journal exists. Its private control directory is outside the three replaced members. The worker checks the exact spent authorization, advances the external generation, stops the installer, creates and verifies a complete encrypted safety copy, and pins the copy outside normal retention. It keeps the original members in the transaction directory. Each rename synchronizes both parent directories. A restarted worker can identify which moves have finished.

The live proof store keeps current consumed IDs and imports historical decisions as spent. Current passkey revocations and counters survive. A recovered-only credential is quarantined. Live audit history stays in place. Historical challenges, enrollment windows and release transactions never authorize work. Before switching, the worker closes unused challenges and windows. These security changes survive an operational rollback.

The restarted installer keeps the job gate closed. A fresh transaction-specific probe runs all required confinement checks. The worker verifies the installer socket, both services, the owner endpoint under the owner's identity, the package version in the probe result, and the restored member hashes. A failed check initiates automatic rollback and a fresh verification of the original state. If recovery cannot verify the original, a durable safe-mode record keeps the gate closed and exposes limited recovery status. The original files, failed candidate and encrypted safety copy remain available for independent inspection.

## Disposable verification

Use the documented offline suites in [the handoff](HANDOFF.md). The focused regression file is `tests/test_root_restore.py`. It uses temporary synthetic vaults, the real proof and socket handlers, SQLite and file locks. It covers interruption at journal and rename boundaries, including a worker process killed after moving an original member. Service transitions and confinement outcomes are controlled by disposable fixtures. Boot-level activation, loss of power to a filesystem and the complete service health path require a disposable systemd guest.
