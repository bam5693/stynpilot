# StyNpilot development handoff

## Current development

Dev23 Stage 2 is released as `0.1.0~dev24` at `3a7aaf2c0c8e71af442803abf9c660942318f0c6`. Independent release verification recorded reproducible builds, 915 passing tests, 95 skips and all 21 confinement checks passing. The package SHA-256 is `4d23df45c1216354cd96dff0b77ef55b2a5abe12548f206f78c84dd00ad97d10` (352,632 bytes).

Dev23 Stage 3 targets `0.1.0~dev25` on `codex/dev23-stage3-root-restore`, based on that release. The new YELLOW request recovers installer records from one complete verified root archive. The owner confirms the archive fingerprint, settings-preserving scope and security-state binding with an enrolled passkey. See the [installer restoration design](DEV23_STAGE3_ROOT_RESTORE.md).

ChatGPT independently reviews the exact candidate recorded in the private master plan. A booted disposable guest is the next integration boundary for systemd, owner-endpoint health and the full confinement probe together. Live restoration is outside the review procedure.

## Dev26 repository management review

The Dev26 candidate combines verified StyNpilot checkout and fetch, offline branch and commit operations, and a passkey-approved native work-branch push. Push binds the repository, local branch, exact commit, and expected remote head. A missing expected remote head is encoded as forty zeroes for branch creation. Native Git performs the update without force, and an independent transport verifies the resulting remote ref.

The transport needs a separate owner-provisioned GitHub credential with write access limited to the StyNpilot repository. Store it as the installer-owned mode-0600 file `repository-github-token` in the installer state directory. The workspace runner never receives it. The release signing credential stays separate.

After independent review and activation, prepare an exact GitHub revision with the live release authority, obtain its `checkout_bundle_sha256`, and consume it through `workspace_fetch_stynpilot`. Confirm the exact new local ref and compare the workspace HEAD before and after. Preserve occupied workspaces. The NIC-free packaged fixture tests the combined MCP workflow against a disposable HTTPS smart-Git origin and synthetic credential.

## Milestones and versions

| Milestone | Scope | Debian package |
| --- | --- | --- |
| Dev22 | Encrypted backup vaults, verification and drills | `0.1.0~dev22` |
| Dev23 Stage 1 | Retention policy and periodic verification | `0.1.0~dev23` |
| Dev23 Stage 2 | Secure key rotation | `0.1.0~dev24` released |
| Dev23 Stage 3 | Installer-side restoration and development lab | `0.1.0~dev25` released |
| Repository management | StyNpilot checkout, fetch and guarded native push | `0.1.0~dev26` candidate |
| Dev23 Stage 4 | Owner-side restoration | Following unused increment |

Dev24 off-machine backup and Dev25 repository management are milestone labels. Every separately published package consumes a version increment.

## Test evidence

The released Stage 2 baseline is 830 passed / 92 skipped in the unprivileged pytest profile and 915 passed / 95 skipped in the disposable release profile. The private review record ties each Stage 3 suite result to an exact Git commit.

Run `./scripts/check.sh` for the full offline unittest entry point. The normal pytest comparison uses the following command. Record the executing UID and environment. Root-only cases skip under an unprivileged user.

```sh
PYTHONPATH=src python3 -m pytest -q -p no:cacheprovider tests --ignore=tests/test_g7.py --ignore=tests/test_compat_check.py
```

The disposable release profile runs the **entire** tests directory, including the two files excluded above. It uses the pinned wheel from `packaging/vendor.lock`, a nonprivileged fixture UID, the release syscall and address-family restrictions, private temporary storage and offline execution. The historical `tools/diagnostics/emulate_release_test_phase.sh` expects a prepared throwaway guest and replaces scratch directories. Use the private handoff for the exact candidate, commands, environment and counts. The release authority separately records its own reproducible builds, tests and package inspection.

## Continuity

[AGENTS.md](../AGENTS.md) contains the standing coding, review and release instructions. The authorized private master plan contains deployment evidence, operational constraints, the approved restoration architecture and the deferred tracker. Preserve all backup generations, recovery material and worktrees.

Open follow-ups include controlled key retirement after external recovery, safe automatic owner pruning, confinement-version reporting, fresh backup verification and independent published-asset verification. The restore stages retain owner/root separation, exact scoped approval, durable replay protection and a verified rollback path. Related design references are [backup vaults](DEV22_BACKUPS.md), [retention](DEV23_STAGE1_RETENTION_AND_VERIFICATION.md) and [release authority](DEV16_RELEASE_AUTHORITY.md).
