# Claude Code runner M1

This is a local prototype for StyNpilot Founder Edition. It connects the existing
task-board lease model to the unmodified Claude Code command-line program.

## M1 boundary

- Claims one task as its separately enrolled Claude runner identity.
- Resolves the board's project name through an owner-maintained workspace map; task
  text cannot choose an executable or filesystem path.
- Refuses to claim work unless `claude auth status --json` reports a logged-in
  `claude.ai` account. `ANTHROPIC_API_KEY`, cloud credentials, and other inherited
  provider variables are not passed to the child.
- Runs Claude Code with `--restricted`, `--permission-mode plan`, and only the
  `Read,Glob,Grep` tools. It does not expose shell, edits, writes, installs, owner
  approvals, or review verdicts. Session persistence is disabled.
- Denies reads of the runner's Claude config directory and common secret-file
  patterns, blocks file-tool access outside the current working directory, caps
  runtime and output, and interrupts the process group when its board lease is lost.
- Uses the board's existing lease expiry/requeue behavior after a runner crash.

The runner is deliberately planning-only. A future execution mode needs an
independently reviewed OS sandbox, workspace write boundaries, bounded test
commands, and owner-mediated YELLOW operations. The Python module is not itself a
sandbox, and passing stub tests does not prove the host service is isolated.

## Local tests

Run `./scripts/check.sh`. The runner tests invoke a temporary stub named
`claude-stub`; they make no network calls, use no Claude account, and never touch a
Ryzen or Pi. They cover subscription-method gating, environment scrubbing,
read-only flags, bounded output, cancellation, and the runner's non-root check.

The runner expects Claude Code with `--restricted` support (2.1.248+) and the JSON
`authMethod` field in `claude auth status` (2.1.268+). It must fail closed on older
versions. Subscription login must happen in the dedicated runner account through
Anthropic's own CLI flow; do not copy the owner's CLI credentials into the runner
account. This local prototype is not a hosted service and must not route other
users' subscription credentials.
