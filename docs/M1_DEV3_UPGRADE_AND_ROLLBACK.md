# M1 dev3: OAuth scope challenge (upgrade from dev2, rollback to dev2)

Nothing here has been run on the Ryzen. It waits for ChatGPT's independent review and the owner's explicit approval.

## Evidence that led to it
dev2 is live and its diagnostics were used: ChatGPT's software search works (GREEN), but its install request returned
`insufficient_scope_workspace_propose`. Its token verifies for `health.read` but lacks `workspace.propose`, although the
discovery document advertises both, both Auth0 grants allow both, and a clean reconnect did not change it. OpenAI's
connector documentation describes `scopes_supported` as a descriptive list and shows the scope inside the 401
`WWW-Authenticate` challenge; the SDK's challenge names no scope, so ChatGPT is never told to ask for `workspace.propose`.

## What changes (src/stynpilot/server/run.py: `ScopeChallenge`; tools list in propose_tools.py)
1. Every `WWW-Authenticate: Bearer` challenge now also carries `scope="health.read workspace.propose"` (read-only builds: `health.read`).
2. A `tools/call` for `commander_request_software_install`, `commander_software_install_status` or
   `commander_request_software_rollback` made with a token that VERIFIES but lacks `workspace.propose` gets an HTTP 403
   `insufficient_scope` challenge naming the scopes, so the client can ask the owner for the missing permission.

## What does not change
- No check is weakened. This layer never admits anything: tokens are still verified by the SDK, and every tool still runs
  its own checks (scope, enrolled client, device grant, no review scope). Owner approval is untouched.
- Search, health, inventory and the catalog stay GREEN with `health.read` (never stepped up).
- A token that does not verify still gets the plain 401, with no step-up hint. Malformed JSON, bodies over 256 KiB and
  unknown Host names pass through unchanged.
- Auth0 settings are not touched.

## Rollback chain
dev3 (candidate) -> **dev2** (immediate rollback; `stynpilot_0.1.0~dev2_all.deb`, sha256 `1a488089...a4c35`, currently
installed) -> dev1 (`f055d1dd...a66ed`) -> dev0 (`b3d639bd...91cf`) -> Preview26. Keep every file and backup.

## Upgrade (only after explicit owner approval)
As in docs/M1_DEV2_UPGRADE_AND_ROLLBACK.md, with dev3 and `stynpilot_0.1.0~dev3_all.deb`: check version and doctor, verify the
checksum (`(umask 022; sh tools/get_release.sh COMMIT SHA256)`), fresh backups, `sudo apt-get install` the package,
`stynpilot stop`, `stynpilot start`, `stynpilot doctor`, refresh both connectors. Then ChatGPT disconnects and reconnects the
connector (the new challenge is what it should now follow) and files a test request; Claude's flow must still work.

## Rollback to dev2
`stynpilot stop`; `sudo apt-get install --allow-downgrades ~/stynpilot-releases/stynpilot_0.1.0~dev2_all.deb`;
`stynpilot start`; `stynpilot doctor`.

## If ChatGPT still cannot get the scope after dev3
Then the connector is not asking for scopes from the challenge either, and the remaining lever is the authorization server
side (for example which scopes Auth0 returns when none are requested), which is the owner's decision and a separate change.
