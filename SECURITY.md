# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via **GitHub → Security → Report a vulnerability** on this repository (GitHub private vulnerability reporting). Don't open a public issue for security bugs. You'll get an acknowledgement within 7 days; fixes are coordinated before disclosure.

## Supported versions

Only the latest release receives security fixes.

## The read-only guarantee

This project is strictly read-only against your tenant, enforced in layers:

1. **Entra permission layer (the one that counts):** the documented app registration holds only delegated read scopes. Even a fully compromised server process cannot take response actions or write to your tenant, because the identity it wields was never granted the ability to.
2. **Code layer:** no write/action endpoint is called anywhere in the codebase; CI review and the project's build spec treat adding one as a breaking security change.
3. **Policy layer:** response actions are explicitly out of scope for this project — not deferred, excluded.

## Threat model summary

| Threat                                         | Mitigation                                                                                                                                                                                                                                                                                                     |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Standing credential theft                      | No app-only credential exists. stdio mode: per-user tokens cached encrypted via the OS keystore (never plaintext; the server refuses to fall back). HTTP mode: user tokens are validated per request and OBO results held in memory only.                                                                      |
| Bulk telemetry exfiltration via the AI channel | Row + byte caps on every response, enforced truncation notices, append-only audit log of every query.                                                                                                                                                                                                          |
| Tenant API quota exhaustion (availability)     | Client-side token-bucket limits set below Microsoft's published quotas; `Retry-After` honoured with capped backoff.                                                                                                                                                                                            |
| Prompt injection via telemetry                 | Alert titles, file names, command lines, and email subjects are attacker-influenceable. The server returns results inside clearly delimited untrusted-data blocks and rejects KQL routes to external data (`externaldata` and `adx()`). Your AI harness must also treat tool output as data, not instructions. |
| Network exposure (HTTP mode)                   | Binds loopback by default; TLS is expected at a reverse proxy; inbound tokens are fully validated (signature, issuer, audience, expiry) before any downstream call.                                                                                                                                            |
| Cross-user continuation token disclosure       | HTTP-mode continuation tokens are tenant-wide opaque random values, bounded and short-lived. A token disclosed to another user can reveal the shape of the original query, but downstream data access is always re-authorised with the redeemer's own delegated identity.                                      |
| Malformed/hostile API responses                | All external input — config, tool arguments, and Microsoft API responses — is schema-validated at the boundary.                                                                                                                                                                                                |

## Deployment hardening checklist

- Keep the app registration read-only; never add `.ReadWrite` or Application permissions to it.
- Scope analyst access with Defender RBAC/device groups — the server inherits it.
- HTTP mode: TLS in front, loopback bind behind, client secret/cert stored in a secret manager (it enables OBO only, not app-only access — but protect it anyway).
- Ship `audit.jsonl` to your log platform; it's your record of what AI agents actually queried.
- Watch Conditional Access sign-in logs — every query is attributable to a real user identity.

## What this server never does

No response actions. No writes. No outbound connection to any host except your tenant's Microsoft endpoints (Graph, the MDE API, and Entra for token acquisition). No telemetry or analytics emitted by the server. No logging of query _results_ (only query metadata).

## What this server cannot protect you from

**Your AI client sends tool results to its model provider.** That is what an MCP server is for. This server hands Defender data to the client that called it; the client then transmits that data to Anthropic, OpenAI, Google, or wherever your model runs. Nothing in this codebase can prevent, inspect, or audit that hop — the audit log records what was _queried_, not where the answer subsequently went.

Deploying this server is therefore a decision to send security telemetry to your chosen AI provider. Assess that provider's data handling, retention, training-use and jurisdiction alongside this server, not separately from it. If that is not acceptable for your data classification, self-host a model or do not deploy this. See [`docs/security-assessment.md`](docs/security-assessment.md) risk **R1** for the full treatment.
