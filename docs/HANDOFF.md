# StyNpilot development handoff

## Current development

Dev23 Stage 2 is released as `0.1.0~dev24` at `3a7aaf2c0c8e71af442803abf9c660942318f0c6`. Independent release verification recorded reproducible builds, 915 passing tests, 95 skips and all 21 confinement checks passing. The package SHA-256 is `4d23df45c1216354cd96dff0b77ef55b2a5abe12548f206f78c84dd00ad97d10` (352,632 bytes).

Dev23 Stage 3 targets `0.1.0~dev25` on `codex/dev23-stage3-root-restore`, based on that release. The new YELLOW request recovers installer records from one complete verified root archive. The owner confirms the archive fingerprint, settings-preserving scope and security-state binding with an enrolled passkey. See the [installer restoration design](DEV23_STAGE3_ROOT_RESTORE.md).

ChatGPT independently reviews the exact candidate recorded in the private master plan. A booted disposable guest is the next integration boundary for systemd, owner-endpoint health and the full confinement probe together. Live restoration is outside the review procedure.

## Dev26 repository management review

The Dev26 candidate combines verified StyNpilot checkout and fetch, offline branch and commit operations, and a passkey-approved native work-branch push. Push binds the repository, local branch, exact commit, and expected remote head. A missing expected remote head is encoded as forty zeroes for branch creation. Native Git performs the update without force, and an independent transport verifies the resulting remote ref.

The transport needs a separate owner-provisioned GitHub credential with write access limited to the StyNpilot repository. Store it as the installer-owned mode-0600 file `repository-github-token` in the installer state directory. The workspace runner never receives it. The release signing credential stays separate.

After independent review and activation, prepare an exact GitHub revision with the live release authority, obtain its `checkout_bundle_sha256`, and consume it through `workspace_fetch_stynpilot`. Confirm the exact new local ref and compare the workspace HEAD before and after. Preserve occupied workspaces. The NIC-free packaged fixture tests the combined MCP workflow against a disposable HTTPS smart-Git origin and synthetic credential.

## Phone-based GitHub credential review

The Dev27 candidate adds `commander_request_stynpilot_credential_setup`. Its MCP arguments contain only the enrolled device and repository. The private approval page accepts the fine-grained token in a masked field and binds the entered value to the existing WebAuthn challenge. The authenticated broker writes the credential atomically to its protected installer state only after verifying that exact value and consuming the independent approval. The token is absent from tool arguments, request records, status and backup payloads.

Provision a GitHub fine-grained token for only the StyNpilot repository with Contents read and write. A saved credential means local provisioning succeeded. A separately approved work-branch push verifies real repository access after activation. The transport now sets `LimitCORE=0` and requests a stop on timeout. Treat a lost push response as uncertain and inspect the remote ref before repeating the operation.

## Full-history intake review

Dev27 is active. The archive review adds read-only HTTPS intake for an exact broker-admitted GitHub, GitLab, or Forgejo repository. It verifies the pinned branch and tag inventory and default HEAD before and after fetching into a fresh bare repository. It verifies full object integrity with strict Git fsck and publishes the bundle and independently bound receipt in a single no-replace rename after syncing both files. Restoring the receipt creates an isolated bare comparison repository with the verified default branch. The archive covers Git objects reachable from the advertised branches and tags. Hidden or deleted refs, submodule repositories, Git LFS contents, and other forge assets require separate preservation.

Before adding a live MCP route, run this worker in a broker-managed transient unit with private storage, an aggregate allocation limit, and a full deadline. Enroll each exact source independently and pass its read credential through the unit. The review tests use synthetic repositories and verify the local Git fetch and archive path. Packaged HTTPS and live provider acceptance remain open.

The Dev28 review adds read-only MCP access to existing imported archives. An owner uses `stynpilot archive-adopt` with the approved manifest digest, bundle digest and enrolled client name. Adoption reconstructs an isolated bare repository offline, reserves capacity before staging, and atomically publishes the verified files and client grant. It does not run Git hooks, select a development baseline, update a worktree, contact a remote or accept archive paths from MCP. Startup reconciles an interrupted adoption before opening the MCP listener. An unavailable archive store does not prevent the rest of the owner service from starting.

The authenticated client can list its archives, page refs and commit links, inspect a commit tree, read small text files, and compare two commit trees when it has access to both archives. This mode covers inspection. The separate remote intake worker still requires provider authorization and an approved broker route. Test the package with `tools/dev/restore-media.sh PACKAGE --archive-mcp-case` and require `STYNPILOT_PACKAGED_ARCHIVE_MCP_OK` and `FIXTURE_EXIT=0` from the disposable guest.

The private-history follow-up applies the existing secret-name policy to historical paths and redacts recognized credentials in the entire returned text. Contents of the original blob and bundle stay byte-identical. Protected paths are withheld from tree and comparison output. Redaction is heuristic, and private-archive grants remain an explicit owner decision. The read routes recheck retained storage and refuse inspection if recovery is unresolved or the store is unsafe or exceeds capacity.

## Private repository authorization review

Dev29 adds passkey-approved, client-specific and expiring private repository grants. The GitLab adapter uses an owner browser device sign-in, exact configured provider and repository, a pinned dedicated project-only provider account, and `read_repository` scope. The installer verifies the provider application, account and scope before retaining a credential. It renews on demand and requires a new sign-in after an uncertain refresh. The phone can revoke a grant or suspend and resume private access through new approved requests. Secrets stay in installer state, outside MCP, logs and the workspace runner. Push uses its separately approved policy and credentials.

The broker must have an independently verified project-only GitLab account and a public device-flow application registered for `read_repository`. Their public identifiers and the exact HTTPS repository are set in the root-only `repository-authorization.json`. Without an enrolled source, the managed path refuses access. A GitLab grant pools no privileges across accounts. The repository readiness tool verifies native private Git read access without transmitting the credential or repository content to the client. The full private bundle transfer into the owner archive store is a separate remaining integration.

GitHub App installation credentials can be narrowed to one repository with Contents read-only. Forgejo's OAuth authorization follows the user account's full rights, so this build leaves it disabled. A repository-specific Forgejo provider grant still needs an approved credential lifecycle. No broad OAuth or PAT fallback is offered by the new path. Run `restore-media.sh PACKAGE --repository-auth-case` for the disposable GitLab HTTPS fixture, owner passkey and MCP test with archive regression checks.

## Milestones and versions

Dev30 adds an owner-passkey-approved offline checkout from an existing DeckPlay archive to the fixed empty workspace. The approval binds source, checkout tree, scanner result and expiry. The approved worker publishes a one-commit Git history with the exact reviewed tree and returns the source and snapshot commit IDs. The original history remains private. The installer keeps recovery excluded until the helper's entire cgroup is quiescent and its private staging is cleaned. A refused or interrupted pre-publication checkout leaves the existing workspace intact. Run `restore-media.sh PACKAGE --deckplay-checkout-case` for packaged acceptance.

To ship reviewed work later, apply a reviewed delta from the local snapshot to a fresh branch based on the exact archived source commit or a separately approved successor. Verify the resulting tree, ancestry and tests, and use the separate repository-specific push authorization. Keep the one-commit snapshot and original archive as provenance.

| Milestone | Scope | Debian package |
| --- | --- | --- |
| Dev22 | Encrypted backup vaults, verification and drills | `0.1.0~dev22` |
| Dev23 Stage 1 | Retention policy and periodic verification | `0.1.0~dev23` |
| Dev23 Stage 2 | Secure key rotation | `0.1.0~dev24` released |
| Dev23 Stage 3 | Installer-side restoration and development lab | `0.1.0~dev25` released |
| Repository management | StyNpilot checkout, fetch and guarded native push | `0.1.0~dev26` released |
| GitHub credential setup | Phone entry and transport hardening | `0.1.0~dev27` released |
| Repository archives | Scoped archive inspection and adoption | `0.1.0~dev28` candidate |
| Private repository authorization | Phone passkey grant and guided GitLab read authorization | `0.1.0~dev29` candidate |
| DeckPlay checkout | Phone-approved history-isolated working snapshot | `0.1.0~dev30` candidate |
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
