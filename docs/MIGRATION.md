# Migration from the GitLab prototype

Source: GitLab project 88825825, MR !27 branch `work/preview15-private-testing-integration-20261119`.
The GitLab project stays untouched as the historical record and the source of the live Ryzen package.
Code moves here one component at a time, only after review, and always with its tests.
Device IDs, hostnames, emails, Auth0 values and backup data are never copied.

## Migrated (in this repository, with tests)

| Here | From GitLab | Changes |
| --- | --- | --- |
| `stynpilot/policy.py` | `tools/commander_policy.py` | One table validator; the owner's four "always ask me" rules added as YELLOW |
| `stynpilot/board.py` | `src/commander_coordination.py` | Review tasks (different reviewer, verdict, 3-round cap), nesting limit, `pr:` claims, cancellation signal |
| `stynpilot/plan.py` | ChatGPT's commit `0e81d7b1` | Validated content travels with the hash; cross-step package duplicates; one expiry spelling |

## Port next (proven, needs adapting)

Ordered by what the Ryzen needs first.

1. `tools/stynpilot_remote_broker.py`: root broker on a private UNIX socket, single-use owner tokens. Generalize from the Forgejo recipe to executing a `ValidatedPlan`.
2. `src/commander_health_connection.py`, `mcp_token_verifier.py`, `mcp_read_router.py`: the MCP endpoint and token checks ChatGPT already uses on the Ryzen.
3. `src/stynpilot_files.py`, `stynpilot_file_tools.py`, `stynpilot_file_changes.py`: enrolled folders and USB with path and symlink safety.
4. `src/commander_phone_bridge.py`, `commander_approval_api.py`, `stynpilot_phone_assets.py`: the phone approval page.
5. `tools/commander_activation_attestation.py`: root-signed activation. This was the fix for the systemd user-namespace issue.
6. `tools/commander_backup_*`, `commander_recovery_supervisor.py`: backups and rollback.
7. `tools/build_desktop_deb.py`, `stynpilot_ryzen_doctor.py`, `stynpilot_ryzen_preflight.py`: packaging and health checks.
8. `tools/stynpilot_local_worker.py`, `stynpilot_pi_link.py`, `stynpilot_dev_inbox.py`: local AI and the Pi link. These come later.

## Retire (not migrated)

- One-off live scripts: `tools/activate_pi_live_*`, `pi_live_*`, `prepare_pi_live_*`, `verify_pi_live_*`, `pi_stage*.sh`. Each fixed one past situation.
- Legacy DeskTether code: `desktether*.py`, `START_DESKTETHER.sh`, `legacy/`.
- Release signing: `release_signing_kit.py`, `STYNPILOT_RELEASE_SIGNING.md`. The owner removed mandatory signing on 2026-11-19.
- Round and handoff notes: `src/ROUND*`, `*_HANDOFF*.md`, `*_REVIEW_2026*.md`, `src/runtime_proposal_test_update.patch`. These are historical. Decisions stay in the GitLab Vault.
- About 40 top-level planning documents. They're replaced by short docs written alongside working code.

## Not yet reviewed in detail

The desktop GUI modules (`desktop_*_gui.py`, `owner_application*.py`) and `customer_*` / `auth0_pairing_adapter.py`. Before migrating, each one gets a keep, port or retire decision based on whether the first-run installer needs it.
