# defender-xdr-mcp — Project Plan

**Status:** approved 29/08/2026 · **Owner:** David (MaddogWarner) · **Architect:** Claude · **Executor:** Codex

## Vision

A self-hosted, strictly read-only MCP server that fronts the Microsoft Defender XDR APIs, letting orgs on M365 E5 (without Sentinel) connect their own AI agents — Claude, Claude Code, VS Code, Codex, Gemini — to their Defender telemetry for AI-assisted hunting, incident triage, and vulnerability discovery. Production-grade and security-first: something a real org's security team could put through review and deploy.

## Locked decisions

| Area           | Decision                                                                                                                                                                    |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Auth           | Delegated per-user only (device code for stdio; auth code + PKCE / OBO for HTTP). No app-only flow. Defender RBAC and Entra per-user audit are preserved end-to-end.        |
| Scope          | Strictly read-only, enforced at the Entra permission level. No response actions — not now, not on the roadmap.                                                              |
| v1 domains     | Advanced hunting (KQL), incidents & alerts, vulnerabilities & device inventory. Secure Score excluded from v1.                                                              |
| Transports     | stdio (local, per-analyst) + streamable HTTP (shared self-host), one codebase.                                                                                              |
| Stack          | TypeScript strict mode, MCP SDK v2 split packages (`@modelcontextprotocol/server` + `@modelcontextprotocol/node`, protocol 2026-07-28), pnpm 11, ESLint + Prettier, vitest. |
| Guardrails     | All four in v1: KQL query guardrails, client-side rate limiting/backoff, structured audit logging, output size caps.                                                        |
| Repo / licence | `MaddogWarner/defender-xdr-mcp`, public, MIT.                                                                                                                               |

## API targets (verified against Microsoft Learn, 29/08/2026)

| Domain                     | API                                                                                                   | Delegated scope                                                                      | Key limits                                                                |
| -------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| Advanced hunting           | Graph v1.0 `POST /security/runHuntingQuery`                                                           | `ThreatHunting.Read.All`                                                             | ~45 calls/min/tenant; 100k rows; 50 MB/result; 10 min CPU/hr; 200 s/query |
| Incidents                  | Graph v1.0 `/security/incidents`                                                                      | `SecurityIncident.Read.All`                                                          | Standard Graph throttling                                                 |
| Alerts                     | Graph v1.0 `/security/alerts_v2`                                                                      | `SecurityAlert.Read.All`                                                             | Standard Graph throttling                                                 |
| Vulns / devices / software | Defender for Endpoint API `api.security.microsoft.com` (regional: `au.`, `us.`, `eu.`, `uk.`, `swa.`) | `Vulnerability.Read`, `Machine.Read`, `Software.Read`, `SecurityRecommendation.Read` | ~50 calls/min, 1,500 calls/hr                                             |

Notes: the legacy advanced-hunting API (`api.security.microsoft.com/api/advancedhunting`) retires **01/02/2027** and the legacy alerts API retires **15/10/2026** — Graph is the correct long-term target. Vulnerability/inventory data has **no Graph equivalent**, hence the second API family. Device code flow requires "Allow public client flows" on the app registration.

## Phases

| #   | Phase                                 | Milestone (success criteria)                                                                                                                  |
| --- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Scaffold + auth + first hunt          | Device-code sign-in works; `run_hunting_query` returns live results over stdio; lint/typecheck/test green; first SBOM generated from lockfile |
| 2   | Incidents, alerts, vulns, inventory   | All 13 tools registered and returning data; MDE regional endpoint configurable                                                                |
| 3   | Guardrail pipeline + audit            | KQL validator, rate limiter, output shaper wired into every tool; JSONL audit log; heaviest unit coverage on the pure guardrail logic         |
| 4   | HTTP transport + Docker               | Streamable HTTP with Entra bearer validation + OBO; non-root read-only-fs container; compose example works                                    |
| 5   | Docs + release prep                   | README implementation guide validated end-to-end; CHANGELOG for v1.0.0; full test pass                                                        |
| 6   | GitHub phase (explicit go from David) | Repo public with CodeQL, Dependabot, secret scanning + push protection; v1.0.0 release with SBOM attached                                     |

Codex builds Phases 1–5 against `codex-plan.md`, in order, running the verification gate after each step. Claude reviews each phase (correctness, security, plan alignment) before the next starts. Phase 6 never runs without David's explicit confirmation.

## Risks & mitigations

| Risk                                                                                                        | Mitigation                                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tenant quota exhaustion by chatty agents                                                                    | Client-side token-bucket limits set _below_ Microsoft's published caps; honour `Retry-After`; surface quota errors to the agent so it self-corrects |
| Bulk telemetry exfiltration via broad queries                                                               | Row + byte caps per response with explicit truncation notices; audit log of every query                                                             |
| Prompt injection via telemetry content (alert titles, filenames, email subjects are attacker-influenceable) | Results returned as clearly delimited untrusted data; documented posture in SECURITY.md; `externaldata` KQL operator rejected                       |
| Token theft from disk                                                                                       | MSAL token cache encrypted at rest via OS keystore (msal-node-extensions); HTTP mode holds no long-lived user tokens                                |
| Microsoft API drift                                                                                         | Graph v1.0 (not beta) endpoints only; API facts dated in docs; Dependabot + CI catch SDK breakage                                                   |
| Scope creep to write actions                                                                                | Hard rule: read scopes only, checked at review; SECURITY.md states the guarantee                                                                    |

## Verification approach

- Unit tests (vitest) concentrate on pure logic: KQL validator, rate limiter, output shaper, config validation. API clients mocked — no live calls in tests.
- Live smoke test against David's tenant with a low-privilege test account before any release.
- Every codex-plan step ends with a runnable gate: `pnpm lint && pnpm typecheck && pnpm test && pnpm build`.
