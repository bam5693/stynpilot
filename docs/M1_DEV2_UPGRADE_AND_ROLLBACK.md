# M1 dev2: upgrade from dev1, and rollback to dev1

dev2 is a small follow-up to dev1 found by the live acceptance test. Nothing here has been run on the Ryzen. It waits for the
owner's explicit approval and the independent review.

## What changed from dev1
1. Approval page: `Referrer-Policy: same-origin` (was `no-referrer`). Real browsers send `Origin: null` on a form POST under
   `no-referrer`, so the exact-Origin check refused a genuine Approve tap ("Refused."). The check stays strict: `null` and
   foreign origins are still refused. Regression test sends what a real browser sends.
2. Permission split (owner policy: software discovery is GREEN). `commander_software_search` now needs only the read scope
   (`health.read`) and a live owner device, like `computer_inventory`. Filing an install or rollback request still needs
   `workspace.propose`, an enrolled and unrevoked AI client, a device grant and no review scope. Nothing was widened for
   requests, and execution still needs the independent owner approval.
3. A genuine token that lacks `workspace.propose` is told `insufficient_scope_workspace_propose` (and the server logs the
   client and scopes, never the token). A token that does not verify still gets the plain `not_authorized`.
4. Version `0.1.0~dev2`.

## Rollback chain
| Package | Role |
|---|---|
| dev2 | candidate (not installed) |
| **dev1** `stynpilot_0.1.0~dev1_all.deb`, sha256 `f055d1dd...a66ed` | **immediate rollback target for dev2** (currently installed on the Ryzen) |
| dev0 `stynpilot_0.1.0~dev0_all.deb`, sha256 `b3d639bd...91cf` | older rollback; keep |
| Preview26 | older emergency fallback; never modified |

Keep the dev1 file in `~/stynpilot-releases/`. Do not delete dev0, dev1, any backup or Preview26.

## Upgrade (only after explicit owner approval)
1. Verify the dev2 build matches the published checksum (`tools/get_release.sh COMMIT SHA256`, run as `(umask 022; ...)` on the Ryzen).
2. `stynpilot doctor` (clean) and confirm the installed version is `0.1.0~dev1`.
3. Take a fresh `tools/preflight_backup.sh` folder, `stynpilot backup` and `stynpilot root-backup` (see docs/REMOTE_AUTH.md for the password agent).
4. `sudo apt-get install ~/stynpilot-releases/stynpilot_0.1.0~dev2_all.deb`, then `stynpilot stop`, `stynpilot start`, `stynpilot doctor`.
5. Refresh the AI connectors. Then: Approve from the phone (the page must now accept the tap), and ChatGPT's search must work.

## Rollback to dev1
`stynpilot stop`; `sudo apt-get install --allow-downgrades ~/stynpilot-releases/stynpilot_0.1.0~dev1_all.deb`; `stynpilot start`;
`stynpilot doctor`. State and configuration are untouched by a package downgrade. Only if they were damaged, restore from
the fresh backups taken in step 3.

## ChatGPT's connection
Search no longer needs `workspace.propose`. Filing requests still does. If ChatGPT's connection holds only `health.read`,
its install requests will say `insufficient_scope_workspace_propose` until the owner grants it. That is an owner-side
Auth0/connector decision, not changed by this release.
