# Local inference pilot — draft, not released

A paired, enrolled proposer with workspace.propose and the independently approved
local-ai-pilot workspace can submit a short text prompt, read its own result,
or request cancellation. Submission and retrieval require the current runner
gate; cancellation remains possible for an authenticated original caller if the
workspace is removed. All calls use the existing proposal gate, audit and rate
limiter. Results belong to the owner/device/client tuple; they are not shared
between clients. The pilot is volatile, limited to one active job and eight
retained results for ten minutes. It makes a fixed HTTP POST to the local
loopback Ollama endpoint and pinned model. It accepts no caller-selected URL,
model, file path, shell command, or tools. Output is untrusted text only.
Cancellation interrupts the connection and discards output; it cannot prove
the model server immediately stops. Revocation blocks subsequent operations;
already admitted inference may finish within the bounded timeout. The existing
sandbox network policy remains unchanged.

Prerequisite: separately owner-configured Ollama loopback server with resource
limits and the pinned model. This is not an installer, OpenCode tool worker,
general command bridge, or autonomous agent. No prompts or results persisted by
this bridge. Avoid secrets in prompts; the local inference server is a separate
trust boundary. A service restart loses outstanding jobs/results.

Before release: independent review, complete offline/release-sandbox tests,
actual packaged MCP authorization and denial tests, real loopback inference,
timeout/cancel and resource-limit testing, then separate owner approval of the
exact release. Do not deploy while the active recovery candidate remains on hold.
