# StyNpilot development handoff

## Current candidate

Dev23 Stage 2 is secure backup key rotation, package `0.1.0~dev24`. Claude's reviewed application code is `015bb403f769002e3280de25c327684649031750`. The handoff-only commit `f0934ae3307eef474b09f588773f03b5ec53fcc7` is the base of `codex/dev23-stage2-final`. Dev23 Stage 1 at `a611385` is the prior release.

The final correction covers an installer process dying before it records the result of root rotation. Startup now inspects the spent approval and its exact vault evidence before classifying the interrupted run. A matching journal resumes under the existing lock. An exact completed result settles the request. Ambiguous evidence, including a crash before the journal exists, requires owner intervention. The owner service can correct an uncertain receipt when the installer has a verified final result. See [the Stage 2 design and crash boundaries](DEV23_STAGE2_KEY_ROTATION.md).

**Next action.** ChatGPT independently reviews the exact candidate SHA recorded in the private master plan. ChatGPT handles preparation, owner approval and live release verification. Stage 3 starts from the verified released commit after that confirmation. Live key rotation is outside the release verification procedure.

## Milestones and versions

| Milestone | Scope | Debian package |
| --- | --- | --- |
| Dev22 | Encrypted backup vaults, verification and drills | `0.1.0~dev22` |
| Dev23 Stage 1 | Retention policy and periodic verification | `0.1.0~dev23` |
| Dev23 Stage 2 | Secure key rotation | `0.1.0~dev24` candidate |
| Dev23 Stage 3 | Installer-side restoration | Next unused increment |
| Dev23 Stage 4 | Owner-side restoration | Following unused increment |

Dev24 off-machine backup and Dev25 repository management are milestone labels. Every separately published package consumes a version increment.

## Test evidence

| Final candidate check | Result |
| --- | --- |
| Normal pytest, unprivileged | 830 passed, 0 failed, 92 skipped |
| Disposable release-sandbox emulation, full pytest suite | 915 passed, 0 failed, 95 skipped |
| Offline unittest entry point | 1,010 run, 93 skipped, 0 failures or errors |

The final emulation used disposable Bubblewrap namespaces and the repository's release seccomp filter on Ubuntu 26.04 with the pinned MCP wheel. It used the distribution's Python and GNU tar. Both pytest runs reported two dependency deprecation warnings.

The input candidate's reported results were 912 passed / 5 skipped in the normal developer environment and 910 passed / 95 skipped in release-sandbox emulation. The new restart tests use synthetic vaults and terminate the installer process at durable write boundaries.

Run `./scripts/check.sh` for the full offline unittest entry point. The normal pytest comparison uses the following command. Record the executing UID and environment. Root-only cases skip under an unprivileged user.

```sh
PYTHONPATH=src python3 -m pytest -q -p no:cacheprovider tests --ignore=tests/test_g7.py --ignore=tests/test_compat_check.py
```

The disposable release profile runs the **entire** tests directory, including the two files excluded above. It uses the pinned wheel from `packaging/vendor.lock`, a nonprivileged fixture UID, the release syscall and address-family restrictions, private temporary storage and offline execution. The historical `tools/diagnostics/emulate_release_test_phase.sh` expects a prepared throwaway guest and replaces scratch directories. Use the private handoff for the exact candidate, commands, environment and counts. The release authority separately records its own reproducible builds, tests and package inspection.

## Continuity

[AGENTS.md](../AGENTS.md) contains the standing coding, review and release instructions. The authorized private master plan contains deployment evidence, operational constraints, the approved restoration architecture and the deferred tracker. Preserve all backup generations, recovery material and worktrees.

Open follow-ups include controlled key retirement after external recovery, safe automatic owner pruning, confinement-version reporting, fresh backup verification and independent published-asset verification. The restore stages retain owner/root separation, exact scoped approval, durable replay protection and a verified rollback path. Related design references are [backup vaults](DEV22_BACKUPS.md), [retention](DEV23_STAGE1_RETENTION_AND_VERIFICATION.md) and [release authority](DEV16_RELEASE_AUTHORITY.md).
