# Local inference pilot — draft, not released

The pilot is a text-only bridge, not an autonomous coding worker or a command
interface. An enrolled proposer with workspace.propose and the owner-approved
local-ai-pilot workspace can submit a prompt, retrieve its own result, or request
cancellation. The original verified caller, device grant, runner gate, workspace
and exact root-side activity claim are rechecked before inference, periodically
during it, and after a successful response. Authorization failure requests
cancellation and discards output. Polling does not guarantee instant revocation:
a blocked authority probe can leave a job outstanding. The HTTP transport has
its own deadline; no new managed job is admitted while its authority check or
durable claim is unsettled. The original bearer is retained only in the active
job's volatile closure; it is not sent to Ollama, logged or persisted.

One active job, eight retained results, ten-minute access expiry (lazy purge).
Results belong to the owner/device/OAuth-client tuple, not an individual chat.
The endpoint and model tag are fixed. The model tag is not a cryptographic
digest. Prompts, outputs and model context are bounded; generated text is
untrusted and never executed. Existing sandbox network restrictions remain.

## Resource and recovery coordination

The fixed owner-side Ollama service must be running with the required effective
cgroup memory, CPU, swap and task limits, the expected environment, and the
correct loopback listener. Missing or ambiguous observations refuse submission.
Readiness is a snapshot, not ongoing resource enforcement, proxy/egress proof
or model availability proof.

The installer uses its existing exclusive recovery admission barrier to reserve
a durable activity record before the owner-side worker starts. Recovery and
competing managed activities are refused while that record exists. Ordinary
completion additionally requires root-side residual resource checks, including
no model child/group and at most 1 GiB resident cgroup memory, or stopped and
empty service. Uncertain completion, cancellation, timeout and process death
retain the record; closing HTTP does not establish Ollama quiescence.

The YELLOW commander_request_local_ai_settlement tool can file a request for
the exact retained inference claim. Independent owner passkey approval is
required before stopping the fixed service through an unprivileged, bounded
systemd helper. The record is cleared only after stopped/empty/no-listener
checks. The service stays stopped; there is no generic service control or
automatic restart. Failed checks retain the claim. A malformed claim or
interrupted proof-spent operation may require owner intervention.

## Unresolved deployment requirements

Do not deploy while the active recovery candidate remains on hold. The
owner-managed service currently accepts direct local clients, including
OpenCode. The managed claim and point-in-time observations do not exclude
independent traffic or manual service restarts. Establish an explicitly
enrolled service lifecycle and a recovery-safe exclusive access mechanism,
including protection against a stale worker reconnecting after settlement,
before treating B2 as fully resolved. Do not bypass this by clearing the claim
or relaxing the existing sandbox. The current implementation does not prove
root recovery remains safe throughout independent service use.

Required: independent source review; full offline and release-sandbox suites;
actual packaged MCP authorization, two client identities, revocation and
workspace removal; real containment and inference/cancellation/timeout;
actual service/installer/owner process-death and recovery/rollback tests in
disposable guests; service configuration persistence and network exposure
checks; prompt/log privacy; review skipped security tests; separate approval
for the exact signed release. Existing root restore resource exhaustion and
upgrade verification remain open. No live deployment on build evidence alone.
