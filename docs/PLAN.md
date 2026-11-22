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
- [x] PR #2: foundation (GREEN/YELLOW/BLACK policy, task board with
  independent reviews, install-plan checker). Reviewed.
- [x] PR #4: runner M1 skeleton (read-only Claude Code worker).
- [x] PR #5: fixes for the runner review (rate-limit-safe progress, late
  instructions reported, CLI self-check). 90/90 tests pass locally.
- [ ] Review #5, merge it into #4's branch, then the owner merges #2 and #4 into
  `main` (#1 comes in with #2).
- [ ] Wire the task board into the packaged service. It must fail closed.
- [ ] Tests that the runner's user can't reach the approval broker, owner state
  or Docker.
- [ ] Port the broker so it executes only a validated install plan. That gives
  one owner approval per plan, with no per-app installer.
- [ ] Reach parity with the current private build, then package from here.
- [ ] Free local CI on the owner's own machine.

## Handoff
When you stop: tick what's done with evidence (a commit or PR link), write the
exact next step at the top of the private plan, and leave a short note on the
open PR.
