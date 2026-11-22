# StyNpilot

**Status:** Early development. No production release.

StyNpilot is an owner-controlled Linux automation and multi-assistant coordination project. Its goal is to help an owner manage enrolled Linux computers through AI assistants while keeping authorization separate from AI-generated requests.

## Product principles

- **One product and one setup experience:** a graphical installer and clear first-run enrollment.
- **GREEN / YELLOW / BLACK:** routine work is permitted only within an owner-enrolled scope; sensitive changes require exact, independently verified owner approval; prohibited actions remain denied.
- **Independent review:** proposed changes must be tested and reviewed, not accepted just because an AI says they work.
- **Least privilege:** AI workers receive only the file, task, network, and tool permissions required for their assignments. They do not receive root or owner-review privileges.
- **Recoverability:** backups, reproducible installation, rollback, and non-destructive retirement are design goals.
- **Transparent execution:** request, plan, decision, progress, result, and verification should be traceable.
- **Local-first development:** prefer offline tests and no-cost tooling; no unexpected paid services.

## Development status

This repository is a clean foundation. Existing prototypes and historical implementation work are being independently reviewed before selective migration. Nothing in this repository should be treated as a deployable installer or a security-approved release until explicitly verified and tagged.

Development roles: a technical implementation lead, an independent code reviewer, and the human owner who retains final authority for consequential changes.

## Security and privacy

**This is a public repository.** Never commit authentication tokens, passwords, private keys, private machine configuration, pairing identifiers, customer data, backup archives, or operational environment files. Use synthetic example values and fixtures.

Do not grant AI clients owner-review credentials, privileged command execution, or unrestricted Docker access. Maintain authorization checks in the actual operating-system and service boundaries rather than relying on assistant instructions.

## What works so far

The core is standard-library Python (3.11+) under `src/stynpilot/`:

- `policy.py`: the GREEN / YELLOW / BLACK classifier. Fails closed, and BLACK always wins.
- `board.py`: the shared task board for ChatGPT, Claude and local workers. It handles leases, recovery, cancellation, independent reviews and bounded debate.
- `plan.py`: validation of immutable install plans. Approval is one plan, one hash.

None of these modules executes system changes or approves anything. See `docs/MIGRATION.md` for what comes over from the GitLab prototype next.

## Running the tests

```sh
./scripts/check.sh
```

The tests run offline, with no root and no paid services. Run them before every push.

## Contributing

- Make one focused change per pull request, with tests.
- Security-sensitive changes (anything about authorization, approval, execution or secrets) need a review from the other assistant before merging.
- Push finished work in batches, not as many tiny commits.

No license has yet been selected. Publicly viewable source code is not automatically permission to reuse or redistribute it.
