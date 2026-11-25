# Dev16 research: native in-chat approval (ChatGPT / Claude)

Question: can the owner tap Approve inside ChatGPT or Claude and have StyNpilot treat that as independent, request-bound proof?
Short answer: not as proof today. As a convenience layer, partly. dev15 passkey deep link stays the proof path.

## What the platforms provide (sources fetched 2026-11-24)
- ChatGPT (developers.openai.com/plugins/reference): tool annotations `readOnlyHint` / `destructiveHint` / `openWorldHint`; the page says
  they only change how ChatGPT presents a call and servers must still enforce their own authorization. For tools needing confirmation,
  arguments reach the widget after the user approves. Auth is OAuth. Identity hints (`openai/subject`, `openai/session`, userAgent,
  userLocation) are anonymized and "never to be relied on for authorization". No signed approval receipt, no per-call binding found.
  The OpenAI help article on app permissions could NOT be fetched (client error); its contents are unverified here.
- Claude (support.claude.com custom connectors article): per-tool enable/disable, an "Allow always" choice, OAuth sign-in. Interactive
  cards act under the connector's existing permissions. Nothing about request-bound approval or elicitation. "Allow once" is not
  described on that page.
- MCP spec: elicitation form mode returns an unsigned answer via the client; sensitive interactions must use URL mode (opens a browser
  page = what dev15 does). Whether ChatGPT/Claude support either mode was not verified.
- MCP Apps (in-chat widgets): sandboxed iframes; standard permission requests are only camera, microphone, geolocation, clipboardWrite.
  No WebAuthn (`publickey-credentials-get`) in that list. ChatGPT nests widgets in its own sandbox origin; WebAuthn in cross-origin iframes
  needs Permissions Policy delegation (Chrome/Edge only per web.dev) that the HOST must grant. A passkey is bound to our rpId, so
  it could only be asserted from a document on our origin (a nested frame of our approval page), not from the host's sandbox origin.
  Whether either host would delegate that is unknown; community reports show hosts silently withholding even camera. Untested inference.
- Biometrics: neither platform documents exposing native biometric verification to a server. The only verified biometric path is
  WebAuthn user verification (dev15).

## Why a host "Allow" is not our proof
It is the host telling itself the user clicked. The server receives an ordinary authenticated tool call: no signature we can verify, no
binding to action/device/parameters/challenge, and "Allow always" turns it into no click at all. The threat we defend against includes a
compromised assistant/host path. GitLab-style approval works because the host and the account token are the authority; here the root
installer must not trust that path. So it can never authorize YELLOW.

## Safe uses (no weakening of GREEN/YELLOW/BLACK)
1. Mark YELLOW *request* tools `destructiveHint=true` so the host asks before an assistant files a request. Cosmetic spam control only;
   the root installer still demands the passkey/Auth0 proof. (Low risk; candidate for dev16.)
2. Keep one-tap deep link as the proof path (opens straight to the fingerprint/PIN prompt).
3. Experiment (owner device needed, harmless request only): an MCP App widget embedding our approval page in a nested frame with
   `allow="publickey-credentials-get"`, to see whether ChatGPT/Claude mobile ever permit it. If a host does, the proof is still our
   WebAuthn assertion verified by the installer, so nothing weakens. Do not build until a probe shows delegation works.
4. Never: treating host approval, elicitation answers or any tool call as owner proof; storing release signing keys in any widget.

## Plan
No dev16 dependency. Probe (item 3) is a small separate GREEN task after the release publisher; revisit when the OpenAI help page is
readable and Claude's connector docs describe elicitation/UI permissions.

## Experiment: external approval round trip (ships with dev16, not dev15)
Link shape: `https://<approval host>/approve/<rid>?go=1&redirectUrl=<chat url>` (ChatGPT's `openExternal` appends `redirectUrl` itself for
allow-listed domains; the assistant can add `go=1`).
- `go=1`: after the exact summary is on screen, the page asks the phone for fingerprint/PIN after ~1 s. Only APPROVE auto-starts; Deny
  stays a button; cancel/failure leaves the normal buttons. Without `go=1` the dev15 page behaves exactly as before (fallback).
- `redirectUrl`: after the installer accepts the proof the page says "Returning to your chat" and navigates there (~1 s). Only `https` on
  exactly chatgpt.com, www.chatgpt.com or claude.ai, no credentials/port/backslash/control characters (`safe_return`, tested against
  look-alike hosts, userinfo tricks, `//` paths, encodings, oversized input). Anything else is ignored and the status page shows.
- Opening or previewing the link changes nothing (tested); the proof is still the WebAuthn assertion bound to the exact request,
  verified by the root installer. The return is a plain navigation carrying no secret.
- Auth0 fallback path unchanged. Browsers cannot close a tab they did not open, so "return" = navigate back, not close.
Android test (owner device): tap link from chat -> expect fingerprint prompt ~1 s later -> expect landing back in the chat. Record:
whether a link-safety dialog appears, whether the prompt auto-starts, whether Chrome reuses the chat tab or opens a new one.
Not built here: an Apps-SDK card with an in-chat Approve button (needs an OpenAI-registered app and `redirect_domains` approval).
