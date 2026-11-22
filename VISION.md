# StyNpilot — Product Vision

> **Build the computer assistant the owner actually wants:** ask ChatGPT or Claude to do useful work, see what is happening, approve only the actions that need approval, and get a verified result—without living in a terminal.
>
> This is the **product north star**, not a claim that every feature is implemented. See `docs/PLAN.md` for the staged build and its actual status. Private device, account, deployment, and recovery details belong only in the owner's private plan, never in this public repository.

## The experience we are building

**ChatGPT is the owner's primary command center.** The owner describes an outcome in ordinary language ("check why this app isn't working," "install this tool," or "have Claude review this change"). ChatGPT proposes a bounded plan, coordinates the work, shows progress, and reports what was proven.

**Claude is a first-class collaborator, not a replacement command center.** ChatGPT and Claude have separate authenticated identities and can propose approaches, assign bounded tasks, exchange results, question assumptions, and independently review one another through a shared Commander task board. No assistant pretends to see another assistant's private chat: coordination happens through explicit, auditable shared messages and task artifacts. Either assistant can request permitted StyNpilot actions without impersonating the other.

**The owner remains in control.** The founding owner has appropriate administrative capabilities, but AI clients never inherit the owner's authority, approve their own requests, acquire root on demand, or silently expand an approved plan.

A successful interaction should feel like this:

1. The owner asks for an outcome from ChatGPT or Claude.
2. The assistant checks current device and task state, collaborates if helpful, and proposes the smallest useful action.
3. GREEN checks and enrolled development tasks execute within their defined limits. For YELLOW actions, the owner sees the exact effect, affected resources, and rollback or recovery plan in a separately authenticated approval experience on the phone.
4. StyNpilot executes **only** the approved, integrity-checked plan; it tracks status, records relevant outcomes, and refuses changed or expired approvals.
5. The assistant independently verifies the result and explains success, failure, or uncertainty without inventing evidence.

The long-term interaction may surface approval conveniently in the chat experience, **but the authorization must remain an independently authenticated owner decision**, not an AI-authored message or a self-approval.

## Non-negotiable product principles

- **GREEN / YELLOW / BLACK:** GREEN is narrowly allowlisted, low-risk work that can proceed automatically. YELLOW requires independent owner approval for an explicit, bounded plan. BLACK is forbidden even if an AI asks. No hidden "always allow everything" route.
- **Separate identities and least privilege:** owner, ChatGPT, Claude, and local workers are distinguishable in authentication, task leases, logs, scopes, and rate limits. An owner-device grant is not the same as an AI-client identity.
- **Exact plans, not blanket shell access:** typed operations with a pinned resource set, hash/version where needed, expiry, replay protection, and preflight checks. The executor fails closed if the plan or machine state changes.
- **Safety and reversibility:** prefer backups/snapshots where appropriate; preserve user data; provide cancellation, recovery, and verified rollback paths. Never claim rollback was proven unless it was tested.
- **Privacy by default:** private or loopback access until the owner deliberately enables scoped remote connectivity. No public exposure of management services or unfinished setup pages. Never put identifiers, secrets, credentials, personal logs, or machine details into this public repository.
- **Proof before expansion:** real device checks and focused tests before building the next layer. Distinguish `implemented`, `tested locally`, `reviewed`, `deployed`, and `verified live`.
- **Low cost and local-first:** prefer free/self-hosted tools and local compute when practical. Do not initiate paid CI, subscriptions, purchases, or ongoing cloud costs without an owner decision.
- **One product, not a pile of one-off scripts:** small, replaceable modules; documented interfaces; consistent permissions; recoverable upgrades; and a tested path off legacy infrastructure.

## Capabilities StyNpilot should grow into

### 1. Reliable installation and daily use
- A graphical, approachable installer and first-run wizard that sets up identity, pairing, secure connectivity, permissions, and recovery.
- Routine operation from ChatGPT, Claude, or a simple phone interface. Terminal commands should be exceptional troubleshooting tools, not the normal workflow.
- Clear device health, installed-service state, diagnostics, and actionable failures.

### 2. Safe computer management
- Read and manage **owner-enrolled** files and development folders, with confinement against path/symlink escapes and explicit review for changes.
- Run approved bounded tasks: code edits, tests, builds, linting, Git operations, service diagnostics, installs, updates, and maintenance—with progress, cancellation, retry, and recovery.
- Offer a general software installation flow, not a bespoke installer for each app; show versions, origins, ports, data changes, preflight, and rollback before approval.
- Serve approved applications to the owner's devices over a private network, never silently to the whole internet.

### 3. A coordinated AI workforce
- One Commander for shared plans, task claims, checkpoints, review evidence, and audit trails.
- ChatGPT as primary coordinator; Claude as an independent development/review collaborator; optional specialized local workers for coding, testing, security, maintenance, and project support.
- Assistants can compare ideas and challenge each other's solutions. Independent review must be real, not the author approving their own output.
- Optional local inference and agent tools are **later additions**, not prerequisites for the core installation/approval loop.

### 4. More than one computer and more than one project
- Securely enroll and manage additional owner-approved devices without sharing unrestricted credentials between them.
- Help develop and maintain the owner's software projects through the same bounded, observable workflows.
- Preserve interoperability: current systems keep working until their replacements are proven, with a fallback available.

## Milestone order and acceptance gates

The build plan may refine the details, but should keep this dependency order:

1. **Prove observation:** both AI clients can independently read a paired device's health and validate an installed application's real status—not just detect files or an occupied port.
2. **Prove one supervised action:** assistant requests a specific software action; owner reviews and approves separately; executor performs exactly that action; assistant verifies the result.
3. **Prove bounded work:** one enrolled workspace supports safe file operations, tests/builds, task status, cancellation, and independent review.
4. **Prove the owner experience:** graphical install/upgrade, simple phone approvals, backups and rollback, private remote access, and minimal routine terminal use.
5. **Expand carefully:** generalized installs, more devices, then optional local AI workers and self-hosted CI.

**A milestone is not complete because a PR exists or unit tests passed.** Record which checks were actually run, what was deployed, what the owner approved, and what remains unverified.

## Decision rule for contributors

When choosing between a new feature and proving an existing capability, **prove the smallest useful end-to-end path first**. When two designs conflict, prefer the one that keeps the owner in control, is easier to audit and recover, avoids extra cost, and reduces how often the owner must troubleshoot at a keyboard.

This file defines **why** we are building StyNpilot. `docs/PLAN.md` defines **what comes next**. Neither grants permission to deploy or bypass owner approval.
