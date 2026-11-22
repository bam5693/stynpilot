# StyNpilot build plan (public summary)

This is the public, secret-free summary of the build plan. The owner's private
plan has the live-system details (machines, accounts, exact owner commands), and
it is the one to work from. This file only tracks the **work in this repository**.

## Roles
- **Owner:** decides, approves anything live, merges to `main`.
- **Claude:** lead developer. Builds everything and keeps the plan current.
- **ChatGPT:** continuity. When Claude is out of usage, ChatGPT continues the
  private plan from its NOW box, step by step, without redesigning. It also does
  read-only reviews when asked.

## Rules for this repository
- It's **public**. Never commit device IDs, host names, account IDs, tokens,
  logs or personal information.
- Run tests locally (`./scripts/check.sh`, as a non-root user) before every push.
- Every pull request gets a review by the other AI before the owner merges it.
  Merging to `main` is the owner's call.
- An AI never approves its own action. YELLOW actions need the owner's
  approval. BLACK actions are never done.

## Work in this repository, in order
This repository is the fresh start. Useful code from the older GitLab prototype
is ported here one piece at a time, with its tests, until this build replaces
what runs on the owner's computer. `docs/MIGRATION.md` records each port.

- [x] PR #2: foundation (policy, task board, install-plan checker).
- [x] PR #4 + #5: read-only runner M1 and its review fixes.
- [x] PR #7: read-only MCP endpoint core (health, software status, token
  checks, owner/device checks). 110/110 tests pass locally.
- [ ] Endpoint startup: listener, OAuth metadata, identity config, device
  grants and pairing.
- [ ] Software catalog and the install / status / rollback request tools.
- [ ] Root broker that executes only a validated install plan (one owner
  approval per plan, no per-app installer).
- [ ] Owner phone approval.
- [ ] Activation, services, packaging, installer, health doctor, backups.
- [ ] The owner upgrades his computer to this build (the old build is kept for
  rollback). Then the owner merges the PR stack into `main`.
- [ ] Runner on the owner's computer, the first general install, and free
  local CI.

## Handoff
When you stop: tick what's done with evidence (a commit or PR link), write the
exact next step at the top of the private plan, and leave a short note on the
open PR.
