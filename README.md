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

## Contributing

Development procedures, test commands, and contribution guidelines will be added as the architecture and first independently tested implementation are established.

No license has yet been selected. Publicly viewable source code is not automatically permission to reuse or redistribute it.
