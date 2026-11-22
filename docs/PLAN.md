# StyNpilot build plan (public summary)

**Why we're building it:** [VISION.md](../VISION.md) is the product north star
(proposed in PR #8, awaiting the owner's decision). This file says **what comes
next** and how far each piece really is. Neither file grants permission to
deploy or to skip the owner's approval.

The owner's private plan has the live-system details (machines, accounts, exact
owner commands), and it is the one to work from. This file only tracks the
**work in this repository**.

## Roles
- **Owner:** decides, approves anything live, merges to `main`.
- **Claude:** lead developer. Builds and keeps the plan current.
- **ChatGPT:** the owner's command center. It continues the private plan from
  its NOW box when Claude is out of usage, without redesigning, and does
  independent reviews.

## Rules for this repository
- It's **public**. Never commit device IDs, host names, account IDs, tokens,
  logs or personal information. Test fixtures use fictional identifiers.
- Run tests locally (`./scripts/check.sh`, as a non-root user) before every push.
- Every pull request gets a review by the other AI before the owner merges it.
  Merging to `main` is the owner's call.
- An AI never approves its own action. YELLOW actions need the owner's
  approval. BLACK actions are never done.

## How far is each piece?
Each item carries the furthest status it has **actually** reached:

| Label | Meaning |
| --- | --- |
| `draft` | Code is in a draft PR. |
| `tested locally` | Its tests pass on a developer machine (the count is given). |
| `reviewed` | The other AI reviewed it and its findings are fixed. |
| `merged` | The owner merged it into `main`. |
| `deployed` | Running on the owner's computer, with the owner's approval. |
| `verified live` | Proven on the owner's computer with real checks. |

A PR existing, or its unit tests passing, does **not** make a milestone done.

## Work in this repository, in order
This repository is the fresh start. Useful code from the older GitLab prototype
is ported here one piece at a time, with its tests, until this build replaces
what runs on the owner's computer. `docs/MIGRATION.md` records each port.

1. Foundation: policy, task board, install-plan checker (PR #2).
   **Status:** draft, tested locally, reviewed.
2. Read-only runner M1 and its review fixes (PR #4 + #5).
   **Status:** draft, tested locally (94/94). PR #5's second set of fixes awaits re-review.
3. Read-only MCP endpoint core: health, software status, token checks,
   owner/device checks, separate AI-client identity (PR #7).
   **Status:** draft, tested locally (117/117). Review findings fixed, awaiting re-review.
4. Endpoint startup: listener, OAuth metadata, identity config, device grants
   and pairing. **Status:** next.
5. Software catalog and the install / status / rollback request tools.
6. Root broker that executes only a validated install plan: one owner approval
   per plan, no per-app installer.
7. Owner phone approval.
8. Activation, services, packaging, installer, health doctor, backups.
9. **Deployment gate (must pass before step 10):**
   - trusted artifact integrity and provenance: the exact package bytes are
     tied to a reviewed commit by a SHA-256 the owner checks, built
     reproducibly, from a known source;
   - a rollback to the previous build that has been **tested**, not just written;
   - the owner approves the exact upgrade commands.
10. The owner upgrades his computer to this build (the old build is kept for
    rollback). Then the owner merges the PR stack into `main`.
11. Runner on the owner's computer, the first general install, and free local CI.

## Handoff
When you stop: update each item's status with evidence (a commit, PR link or
test count), write the exact next step at the top of the private plan, and leave
a short note on the open PR.
