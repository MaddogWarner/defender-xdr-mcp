# Security assessment pack — defender-xdr-mcp v1.0.0

**Prepared:** 31/08/2026 · **Applies to:** v1.0.0 · **Status:** pre-production, not yet live-verified

This document exists so a security assessor can evaluate this product without reading the source. It provides the architecture, data flows, control inventory, verification status, supply-chain position and a pre-filled risk register.

**It is written by the project's own maintainer.** It is not an independent review, a penetration test, or a third-party assurance report. No such review has been performed. Treat the control claims as assertions to be sampled and verified — every one of them cites a file and line so you can check it yourself.

**Read the residual-risk register (§9) before the control inventory (§6).** The controls are good; the unverified status and the AI-egress question are what actually determine whether you should trial this.

---

## 1. What this product is

A self-hosted [Model Context Protocol](https://modelcontextprotocol.io) server that exposes Microsoft Defender XDR data as read-only tools an AI client can call. It targets organisations with Microsoft 365 E5 (or equivalent Defender licensing) that do **not** run Microsoft Sentinel, and therefore have no existing path to connect AI tooling to their security telemetry.

It is a **read path only**. It exposes advanced hunting (KQL), incidents, alerts, vulnerabilities, devices, software inventory and security recommendations. It cannot isolate a device, suppress an alert, or change anything in the tenant.

**Provenance:** internally developed, single maintainer, MIT licensed, public source. There is no vendor, no support contract, and no commercial assurance behind it. §10 covers what that means for your assessment.

## 2. Deployment models

| Model      | Transport       | Who runs it                                                                  | Authentication                                                               | Typical use                                                |
| ---------- | --------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------- |
| **Local**  | stdio           | One analyst, on their own workstation, as a child process of their AI client | Entra device-code flow; tokens cached encrypted in the OS keystore           | Individual analyst using Claude Code / VS Code / Codex CLI |
| **Shared** | Streamable HTTP | One container, behind a TLS reverse proxy, serving a team                    | Entra bearer token per request, exchanged on-behalf-of for downstream tokens | A team sharing one deployment                              |

Both models run entirely inside your own boundary. Neither calls a vendor backend.

## 3. Architecture and trust boundaries

```text
┌─ Your workstation / your network ─────────────────────────────────┐
│                                                                   │
│  AI client (Claude Code, VS Code, Codex CLI, Gemini CLI)          │
│      │                                                            │
│      │  ── TRUST BOUNDARY 1 ──▶  model provider (see §4.3, R1)    │
│      │                                                            │
│      ▼ stdio (local)  ─or─  HTTPS (shared, via TLS proxy)         │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │ defender-xdr-mcp                                            │   │
│  │   bearer validation (HTTP only) → KQL validator →           │   │
│  │   rate limiter → API call → output shaper → audit log       │   │
│  └────────────────────────────────────────────────────────────┘   │
│      │                                                            │
└──────┼────────────────────────────────────────────────────────────┘
       │  ── TRUST BOUNDARY 2 ──▶  Microsoft, over TLS
       ├── login.microsoftonline.com          (Entra: tokens, JWKS)
       ├── graph.microsoft.com                (hunting, incidents, alerts)
       └── [region.]api.security.microsoft.com (vulns, devices, software)
```

**Boundary 1 — AI client to model provider.** Outside this product's control. This is the boundary that matters most in your assessment; see §4.3 and risk R1.

**Boundary 2 — server to Microsoft.** TLS, Microsoft endpoints only. The server makes no other outbound connection. Continuation URLs returned by Microsoft are validated against an allow-list of expected origins before being followed, so a malformed or hostile `@odata.nextLink` cannot redirect the server to an arbitrary host (`src/clients/continuationTokens.ts:71`).

**Boundary 3 — between users, in shared mode.** Every request is authenticated and authorised independently; downstream Microsoft calls always carry the calling user's own delegated token. See R7 for the one place state is shared.

## 4. Data flows and classification

### 4.1 What data the server touches

| Data                                                                                                                       | Sensitivity                                                                                          | Where it comes from | Where it goes                    |
| -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------- | -------------------------------- |
| Advanced hunting results (process command lines, file paths, device names, user UPNs, email metadata, network connections) | **High** — operational security telemetry, contains PII and identifiers                              | Microsoft Graph     | AI client → model provider       |
| Incidents and alerts, with evidence                                                                                        | High                                                                                                 | Microsoft Graph     | AI client → model provider       |
| Vulnerabilities, devices, software inventory                                                                               | Medium–High — exploitable weakness detail about named assets                                         | MDE API             | AI client → model provider       |
| Analyst identity (UPN, object ID, tenant ID)                                                                               | Medium — PII                                                                                         | Entra token claims  | Audit log; not sent downstream   |
| KQL query text                                                                                                             | Medium — can embed hostnames, UPNs, and in health or welfare contexts, identifiers about individuals | AI client           | Audit log                        |
| Access and refresh tokens                                                                                                  | **Critical**                                                                                         | Entra               | Memory; OS keystore (stdio only) |

### 4.2 What the server persists

Exactly one artefact: the **audit log** (`audit.jsonl`).

| Field                                              | Contains                                          |
| -------------------------------------------------- | ------------------------------------------------- |
| `ts`, `tool`, `durationMs`, `status`, `error.code` | Metadata                                          |
| `upn`                                              | The analyst who made the call                     |
| `args`                                             | Tool arguments, **including full KQL query text** |
| `rowCount`                                         | Number of rows returned                           |

**Result rows are never written to the log** (`src/tools/pipeline.ts`). The log records what was asked, not what came back.

The file is created and repaired to `0600` on every write (`src/audit/log.ts:84`), rotated by size with a configurable retention count, and append-only. Writing to it is **mandatory and fail-closed**: if the audit write fails, the tool call fails (`src/tools/pipeline.ts:104`). A deployment cannot silently run unaudited.

Tokens are never logged or persisted in plaintext. In local mode they are cached via the OS keystore through `@azure/msal-node-extensions`; the server refuses to fall back to an unencrypted cache. In shared mode, on-behalf-of results are held in memory only, capped at 512 entries, and expire at the earlier of the downstream token's expiry or the inbound token's, minus a five-minute skew (`src/auth/obo.ts`).

**Assessor note:** the audit log is your record of AI activity against Defender, and it contains query text. Classify and retain it as you would other security-operations logs, and ship it to your log platform. In a health or welfare context, query text can contain identifiers about individuals.

### 4.3 What leaves your boundary — read this carefully

The **server** sends data only to Microsoft endpoints in your own tenant. That claim is verifiable and it is true.

**Your AI client is a different matter, and it is the main event in this assessment.** MCP exists to feed tool results to a language model. Every row this server returns is transmitted by your AI client to whichever provider serves that model — Anthropic, OpenAI, Google, or a model you host yourself. Self-hosting this server eliminates the hop to a hosted MCP vendor. It does not eliminate, and cannot eliminate, the hop to the model.

In practice, trialling this product means **your Defender security telemetry will be sent to a commercial AI provider**, unless you pair it with a self-hosted model.

Your assessment of this product is therefore incomplete without a parallel assessment of:

- which model provider the client uses, and under what commercial terms;
- that provider's retention period, and whether inputs are used for training (enterprise agreements commonly exclude this — confirm yours in writing rather than assuming);
- the jurisdiction the data is processed in, and whether that satisfies your data-residency obligations;
- whether your organisation already has an approved position for that provider that this use falls inside.

The row and byte caps in this server bound how much data goes per call. They do not change whether it goes.

## 5. Identity and access control

**Delegated per-user authentication only. There is no application-permission mode and no roadmap to add one.** This is the single most important control in the product, because it means the server holds no standing tenant-wide credential that could be stolen and reused.

Every query runs as the signed-in analyst. Existing Defender RBAC, device-group scoping, Conditional Access and Entra sign-in audit all apply unchanged and un-bypassed. The server cannot show a user anything Defender itself would not show them.

### 5.1 Requested scopes — least privilege evidence

| API                | Delegated scope               | Purpose            |
| ------------------ | ----------------------------- | ------------------ |
| Microsoft Graph    | `ThreatHunting.Read.All`      | Advanced hunting   |
| Microsoft Graph    | `SecurityIncident.Read.All`   | Incidents          |
| Microsoft Graph    | `SecurityAlert.Read.All`      | Alerts             |
| Microsoft Graph    | `User.Read`                   | Sign-in identity   |
| WindowsDefenderATP | `Vulnerability.Read`          | Vulnerability data |
| WindowsDefenderATP | `Machine.Read`                | Device inventory   |
| WindowsDefenderATP | `Software.Read`               | Software inventory |
| WindowsDefenderATP | `SecurityRecommendation.Read` | Recommendations    |

Every scope is read-only. **No `.ReadWrite` scope, and no Application permission, appears anywhere in the product or its documentation.** The read-only guarantee is enforced at the Entra permission layer, not merely in code — a fully compromised server process still cannot write to your tenant, because the identity it wields was never granted the ability to.

**Verification for the assessor:** the app registration is created by your own admin, in your own tenant, from the instructions in the README. You control exactly which scopes are granted, you can inspect them at any time, and you can revoke consent unilaterally. You do not have to trust this document on the point — check the registration.

### 5.2 Shared-mode authentication

Inbound bearer tokens are fully validated before any downstream call: RS256 signature against Entra's published JWKS, issuer pinned to your tenant, audience pinned to the app registration, `tid` re-checked against configured tenant, `exp`/`nbf` enforced, and a mandatory `access_as_user` scope (`src/auth/bearer.ts`). Tokens failing any check are rejected with a discoverable 401 and never reach the on-behalf-of exchange.

The public origin is explicitly configured (`DXM_PUBLIC_URL`), not inferred from request headers, so `Host` and `Origin` validation cannot be defeated by an attacker-supplied header — the DNS-rebinding path that header-derived checks leave open is closed.

## 6. Security control inventory

Every control below cites a location. Sample them.

| #   | Control                                                                                                     | Implementation                                | Assurance                                                                                 |
| --- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------- |
| C1  | Read-only enforced at the identity layer                                                                    | Entra app registration holds only read scopes | Verifiable in your own tenant                                                             |
| C2  | Delegated per-user auth; no standing credential                                                             | `src/auth/msal.ts`, `src/auth/obo.ts`         | Unit tested                                                                               |
| C3  | KQL validation — rejects `externaldata` and `adx()`                                                         | `src/guardrails/kqlValidator.ts`              | Unit tested; 100 % line coverage                                                          |
| C4  | KQL string/comment scanner implementing real Kusto grammar; fails closed on unterminated literals           | `src/guardrails/kqlValidator.ts:112`          | Unit tested; verified by adversarial probe                                                |
| C5  | Timespan clamped to a configured maximum                                                                    | `src/guardrails/kqlValidator.ts`              | Unit tested                                                                               |
| C6  | Row cap injected when the query is unbounded, including bounds hidden in subqueries                         | `src/guardrails/kqlValidator.ts:64`           | Unit tested                                                                               |
| C7  | Dual-window rate limiting (per-minute and per-hour) below Microsoft's quotas; retries consume capacity      | `src/guardrails/rateLimiter.ts`               | Unit tested                                                                               |
| C8  | Response row and byte caps with explicit truncation notices                                                 | `src/guardrails/outputShaper.ts`              | Unit tested; 100 % line coverage                                                          |
| C9  | API results wrapped in delimited untrusted-data blocks                                                      | `src/guardrails/outputShaper.ts`              | Unit tested                                                                               |
| C10 | Mandatory fail-closed audit; a call that cannot be audited does not return                                  | `src/tools/pipeline.ts:104`                   | Unit tested                                                                               |
| C11 | Audit file `0600`, append-only, size-rotated, flushed on shutdown                                           | `src/audit/log.ts`                            | Unit tested                                                                               |
| C12 | Full inbound bearer validation before any downstream call                                                   | `src/auth/bearer.ts`                          | Unit tested                                                                               |
| C13 | Explicit configured public origin; `Host` and `Origin` validated against it                                 | `src/http.ts:72`                              | Unit tested                                                                               |
| C14 | Continuation URLs validated against an origin allow-list (SSRF control)                                     | `src/clients/continuationTokens.ts:71`        | Unit tested                                                                               |
| C15 | All config and tool input schema-validated at the boundary (Zod)                                            | `src/config.ts`                               | Unit tested                                                                               |
| C16 | Container: non-root, read-only root filesystem, dropped capabilities, `no-new-privileges`, loopback publish | `Dockerfile`, `compose.yaml`                  | Build, read-only run, health and non-root user CI-verified; mounted audit volume deferred |
| C17 | Secrets excluded from container build context                                                               | `.dockerignore`                               | Reviewed                                                                                  |
| C18 | Static analysis and dependency scanning in CI                                                               | `.github/workflows/codeql.yml`, Dependabot    | Runs on push                                                                              |

## 7. Verification status — what has and has not been tested

**This is the section most likely to determine your risk rating. It is deliberately blunt.**

### Verified

- Repository-wide lint and formatting: clean.
- TypeScript strict compilation (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`): clean.
- **166 unit tests across 22 files: passing.**
- Coverage: **98.96 % lines overall**; guardrails 99.2 %; audit 97.22 %.
- Production build: clean.
- The production image builds and starts in CI with a read-only root filesystem; `/healthz` returns the exact package version and the runtime user is `node` ([CI evidence, 04/09/2026](https://github.com/MaddogWarner/defender-xdr-mcp/actions/runs/33826849251)).
- Every phase reviewed against the build specification before the next began, including adversarial probing of the KQL validator that found and fixed two exploitable defects prior to v1.0.0.

### Not verified

- **The product has never been run against a live Microsoft 365 tenant.** No real token has been acquired, no real query executed, no real API response parsed.
- The container's mounted named-volume audit write (runbook Gate 6d) has not been executed; Docker is unavailable on the maintainer's local host.
- No independent security review or penetration test.
- No load, soak or concurrency testing beyond unit-level.
- Rate limiter behaviour against Microsoft's _actual_ throttling responses is untested.

Every outstanding gate is enumerated with pass/fail criteria in [`live-test-runbook.md`](live-test-runbook.md), with a recording sheet. **Completion of that runbook should be a precondition of any trial**, and its results are the evidence that would let you lower R2.

## 8. Supply chain

- **Six direct runtime dependencies:** `@azure/msal-node`, `@azure/msal-node-extensions`, `@modelcontextprotocol/server`, `@modelcontextprotocol/node`, `jose`, `zod`. All are widely used, and the Azure and MCP packages are first-party to Microsoft and Anthropic respectively.
- **230 total components** including transitive dependencies, recorded in a CycloneDX 1.7 SBOM generated from the lockfile by pnpm's builtin tooling and attached to releases.
- Dependencies pinned via `pnpm-lock.yaml`; container builds use `--frozen-lockfile` and a pinned package-manager version.
- **Dependabot** for npm and GitHub Actions, weekly. **CodeQL** static analysis on push.
- MIT licensed; no copyleft obligations introduced.
- Node.js ≥ 20 required. The container base image is `node:24-alpine`.

**Residual:** 230 transitive components is a real surface, and no software composition analysis beyond Dependabot has been run. See R8.

## 9. Risk register

Ratings are the maintainer's assessment on a standard 5×5 (Likelihood × Consequence). **They are a starting position for you to challenge, not a finding.** Consequence is judged against a security-operations context handling sensitive telemetry.

| ID      | Risk                                                                                                                                                                           | Inherent                          | Existing controls                                                                                                                                                                       | Residual                                                             | Treatment for a trial                                                                                                                                                                                                                                                                            |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **R1**  | **Defender telemetry is transmitted to a commercial AI provider by the AI client.** Not controllable by this product.                                                          | **High** (Almost certain × Major) | Row and byte caps bound volume per call; audit log records every query; self-hosted model is an option                                                                                  | **High** — unchanged by anything in this codebase                    | **Decide this first.** Confirm your provider's retention, training-use and jurisdiction terms in writing. Restrict the trial to a data classification your existing AI position already permits. If no approved position exists, obtain one before trialling — or pair with a self-hosted model. |
| **R2**  | **Product has never run against a live tenant, and the mounted-volume audit write remains unverified.** Unknown behaviour on first contact with real data and real throttling. | **High** (Likely × Major)         | Extensive unit testing; CI-verified container build, read-only startup, health and non-root runtime; documented runbook                                                                 | **Medium** after runbook completion; **High** until then             | Complete `live-test-runbook.md` in full, in a non-production or low-impact context, before any analyst-facing use. Do not waive this.                                                                                                                                                            |
| **R3**  | Prompt injection via telemetry. Alert titles, file paths and command lines are attacker-influenceable and flow into an AI agent's context.                                     | **High** (Likely × Major)         | Untrusted-data delimiters on all output; `externaldata` and `adx()` rejected, closing the external-fetch path                                                                           | **Medium**                                                           | Ensure the AI client treats tool output as data. Prohibit agent configurations that auto-execute actions from tool output. This is a genuine, active risk class — not theoretical.                                                                                                               |
| **R4**  | Audit log contains query text with hostnames, UPNs and potentially identifiers about individuals.                                                                              | Medium (Possible × Moderate)      | `0600`; append-only; rotation; result rows never logged                                                                                                                                 | **Low–Medium**                                                       | Classify as a security log. Ship to your log platform. Set retention per policy. Restrict host access.                                                                                                                                                                                           |
| **R5**  | Single maintainer; no independent security review; no support contract.                                                                                                        | Medium (Possible × Moderate)      | Public source; MIT; documented spec; CodeQL; private vulnerability reporting enabled                                                                                                    | **Medium**                                                           | Accept explicitly as a trial condition, or commission an independent review before production. Assess your own capacity to maintain or fork it.                                                                                                                                                  |
| **R6**  | Shared-mode client secret or certificate compromise. Enables on-behalf-of exchange.                                                                                            | Medium (Unlikely × Major)         | Secret enables OBO only — it cannot obtain app-only access, because no application permission is granted. Read-only scopes cap the blast radius. Excluded from container build context. | **Low–Medium**                                                       | Store in a secret manager. Rotate on schedule. Prefer certificate over secret. Local stdio mode avoids this entirely.                                                                                                                                                                            |
| **R7**  | Cross-user continuation-token disclosure in shared mode reveals another user's query shape.                                                                                    | Low (Unlikely × Minor)            | Tokens are unguessable random values, bounded and short-lived; **downstream data access is always re-authorised under the redeemer's own identity**, so no data crosses users           | **Low**                                                              | Accept. Documented in `SECURITY.md`.                                                                                                                                                                                                                                                             |
| **R8**  | Supply-chain compromise via one of 230 transitive npm components.                                                                                                              | Medium (Possible × Major)         | Lockfile pinning; frozen installs; Dependabot; CodeQL; SBOM published                                                                                                                   | **Medium**                                                           | Accept for a trial with SBOM ingested into your own SCA tooling. Monitor Dependabot alerts.                                                                                                                                                                                                      |
| **R9**  | Defender API quota exhaustion degrades production security tooling.                                                                                                            | Medium (Possible × Moderate)      | Dual-window limiter set below Microsoft's published quotas; retries consume capacity; `Retry-After` honoured                                                                            | **Low–Medium**                                                       | Verify limiter behaviour during the live runbook (Gate 4). Start the trial with a small analyst cohort.                                                                                                                                                                                          |
| **R10** | Excessive data exposure to a curious or malicious insider — an analyst using AI to bulk-query telemetry more efficiently than before.                                          | Medium (Possible × Moderate)      | Server cannot exceed the user's own Defender RBAC; every query attributable and audited; row and byte caps                                                                              | **Low–Medium**                                                       | Review audit log during the trial. Note this changes the _efficiency_ of insider data access, not its _scope_.                                                                                                                                                                                   |
| **R11** | Data residency — telemetry crosses jurisdictions via the AI provider.                                                                                                          | Medium (Possible × Major)         | MDE regional endpoints supported (`au`, `us`, `eu`, `uk`, `swa`, `ina`, `aea`) so Microsoft-side traffic stays in-region                                                                | **Medium** — determined entirely by the AI provider, not this server | Assess with R1. Australian public-sector obligations may constrain provider choice.                                                                                                                                                                                                              |
| **R12** | Public source disclosure aids an attacker targeting a deployment.                                                                                                              | Low (Possible × Minor)            | No secrets in source; security rests on Entra identity and tenant config, not code obscurity                                                                                            | **Low**                                                              | Accept. Open source is a net assurance benefit here — it is what makes this assessment possible.                                                                                                                                                                                                 |

**Highest residual risks: R1 and R2.** R2 is fully treatable — run the runbook. R1 is a policy decision about AI providers that this product cannot make for you and does not materially change; it exists the moment you connect any AI tool to any sensitive data source.

## 10. Framework alignment

Mapped thematically. **Clause-level mapping should be done against your organisation's current policy version — the responsibilities below are shared between this product and your environment, and most of them land on your side.**

### ASD Essential Eight

The Essential Eight are controls for an _organisation's environment_, not for an individual application, so most map only indirectly. Where this product is relevant:

| E8 mitigation                                                                                             | Relevance                                                                                                                                                                         |
| --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Patch applications                                                                                        | Dependabot weekly; SBOM published for your SCA tooling. **Your responsibility to apply updates** — there is no auto-update mechanism.                                             |
| Restrict administrative privileges                                                                        | Strongly aligned. Read-only delegated scopes only; no application permissions; no privilege escalation path; container runs non-root.                                             |
| Multi-factor authentication                                                                               | Inherited from your Entra Conditional Access policies, which apply to the device-code and authorisation-code flows unchanged. This product neither implements nor can bypass MFA. |
| Application control                                                                                       | Your responsibility. This is a Node.js process on a workstation or a container in your environment; control it as you would any other.                                            |
| Restrict Microsoft Office macros · User application hardening · Regular backups · Patch operating systems | Not applicable to this component.                                                                                                                                                 |

### NSW Government Cyber Security Policy

Thematic alignment only; confirm against your current policy version.

- **Risk management** — this document, plus `SECURITY.md` and the live-test runbook, are intended as the evidence base for a formal risk assessment.
- **Identity and access management** — delegated per-user authentication, no shared or standing credential, full attribution of every query to a named user, existing RBAC inherited and un-bypassed.
- **Logging and monitoring** — mandatory fail-closed audit of every tool call, designed for ingestion into your log platform; Entra sign-in logs provide independent corroboration.
- **Information classification and handling** — §4 gives the data inventory. **R1 is the material issue** and is likely to be the determining factor for a NSW public-sector deployment.
- **Supply chain** — §8; SBOM published, dependencies pinned and scanned.
- **Assurance** — **this is the weak point.** No independent review, and the product is not yet live-verified (§7). Both are treatable but neither is currently satisfied.

## 11. Recommended trial conditions

If you proceed to a trial, these are the conditions the evidence supports:

1. **Resolve R1 first.** Obtain or confirm an approved organisational position on the AI provider your client uses. Nothing else matters if this fails.
2. **Complete the live-test runbook in full** before any analyst-facing use, and record the results.
3. **Start local (stdio), not shared (HTTP).** It removes the client secret (R6), the network exposure and the multi-user surface (R7) entirely. Move to shared mode only if the trial justifies it.
4. **Small cohort** — two or three experienced analysts who understand the tooling.
5. **Time-boxed**, with a defined review point.
6. **Ship the audit log to your log platform from day one** and review it at the end of the trial. It tells you what AI agents actually queried.
7. **Restrict the app registration to a Defender RBAC scope appropriate to the trial cohort** rather than granting broad access for convenience.
8. **Define the exit.** Revoking admin consent on the app registration disables the product immediately, tenant-wide, unilaterally — a clean and instant rollback that is worth stating explicitly in your proposal.
9. **Deliberately test prompt injection (R3)** during the trial rather than assuming the control works.

## 12. Open items and known limitations

Carried forward honestly rather than closed off:

- Live tenant gates and the mounted named-volume audit write are outstanding (R2).
- No independent security review (R5).
- Audit file permissions are repaired to `0600` on every write, which will conflict with a deployment deliberately using group-readable log files for a shipping agent.
- The `/healthz` endpoint is unauthenticated and reachable regardless of `Host` header. It returns only a version string.
- An outer `take` followed by `mv-expand` or a join can multiply rows after the validator's bound. The validator does not reject these valid query shapes; the output shaper still enforces the configured row and byte caps before results reach the model.
- Shared HTTP mode requires `requestedAccessTokenVersion: 2` in the Entra app manifest. Entra-only registrations otherwise issue v1.0 tokens with an `https://sts.windows.net/` issuer, which this server rejects by design; the verifier is not widened to accept v1.0 issuers.
- No software composition analysis beyond Dependabot.
- Rate limiter tuning is based on Microsoft's published quotas as verified on 29/08/2026 (`api-verification.md`); those quotas can change without notice.

## 13. Reference documents

| Document                                       | Contents                                                                                     |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [`../README.md`](../README.md)                 | Implementation guide, tool inventory, app registration setup                                 |
| [`../SECURITY.md`](../SECURITY.md)             | Threat model, read-only guarantee, hardening checklist, vulnerability reporting              |
| [`live-test-runbook.md`](live-test-runbook.md) | Six ordered verification gates with recording sheet — **the outstanding assurance evidence** |
| [`http-deployment.md`](http-deployment.md)     | Shared-mode deployment, TLS proxy configuration, client provisioning                         |
| [`api-verification.md`](api-verification.md)   | Microsoft API endpoints, scopes and quotas as verified at build time                         |
| [`clients.md`](clients.md)                     | AI client configuration                                                                      |
| [`../codex-plan.md`](../codex-plan.md)         | Full build specification and per-phase review record                                         |
| `sbom.cdx.json`                                | CycloneDX 1.7 SBOM (attached to releases)                                                    |
