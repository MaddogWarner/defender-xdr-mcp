# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.4] - 14/11/2026

### Security

- `get_incident`, `get_alert` and `get_device` reject `.` and `..` as record IDs, which URL normalisation would otherwise collapse into a different request path.
- Untrusted-telemetry delimiters now carry a random per-response id, so telemetry containing the delimiter text cannot imitate the end of the block.
- Audit entries record the caller's immutable Entra object ID (`oid`) alongside the UPN when it is known.
- HTTP mode writes a one-line notice to stderr, carrying the failure code only, when a bearer token is rejected.
- Set the MCP SDK's `maxToolInputElements` limit (GHSA-46jr-4wx8-v453).
- GitHub Actions are pinned to commit SHAs and the container base image to a digest; Dependabot now also tracks the Docker base image.

### Changed

- `DXM_HUNTING_RPM`, `DXM_HUNTING_RPH`, `DXM_MDE_RPM` and `DXM_MDE_RPH` are rejected at startup above Microsoft's published quotas (45, 1,500, 50 and 1,500).
- `run_hunting_query` rejects queries longer than 100,000 characters.
- `get_connection_status` output includes `oid` when known.

## [1.1.3] - 13/11/2026

### Security

- Closed two KQL validator bypasses in `run_hunting_query` where the string/comment scanner disagreed with Kusto's lexer, letting a rejected external-access call hide in text the scanner treated as a literal or comment. The scanner now recognises `~~~` multi-line literals as well as triple backticks, and ends a line comment at a bare carriage return, U+2028 or U+2029 as well as a line feed.

### Changed

- A raw carriage return or line feed inside a single-line string literal is now rejected as an unterminated literal. Kusto ends the literal at that point, so such a query was never valid.

## [1.1.2] - 10/10/2026

### Security

- Strengthened KQL external-data validation in `run_hunting_query` (GHSA-v95r-2cwr-x73x).

## [1.1.1] - 09/09/2026

### Fixed

- Enforce rolling minute request limits so an initial burst plus refills cannot exceed the configured RPM; retain rolling hour limits and retry accounting.
- Withhold continuation tokens on truncated list pages and require a smaller-page restart, preventing next-page navigation from skipping omitted records.
- Force MSAL silent refresh after stdio token invalidation and bypass MSAL's secondary OBO cache when the shared bounded cache needs a new token.

## [1.1.0] - 04/09/2026

### Fixed

- Isolated the stdio-only encrypted token-cache dependency from HTTP startup, included pnpm's approved-build policy in the container build context, and added CI checks for image build, read-only startup, exact health response and non-root execution.
- Deferred Graph and Defender on-behalf-of exchanges until a tool needs the relevant resource, with safe model-readable guidance for MSAL failures and retryable failed exchanges.
- Added `node dist/index.js --sign-in` so stdio users can complete Graph and Defender device-code authentication before connecting an MCP client.
- Inserted the server KQL row cap before a trailing `render` operator so generated queries remain valid.

### Changed

- Corrected deployment, client, runbook and assessment guidance for Entra v2 access tokens, tenant-wide hunting quotas, Graph page-size limits, reverse-proxy request-body limits, expanded live tool coverage, and CI-verified container controls.

## [1.0.0] - 30/08/2026

### Added

- Project inception (29/08/2026): architecture, build specification (`codex-plan.md`), and documentation set (README, SECURITY, project plan).
- Repository scaffolding: MIT licence, CI (lint/typecheck/test/build), CodeQL code scanning, Dependabot (github-actions + npm, weekly), CycloneDX SBOM generation on release, Dockerfile + compose.
- Phase 1 implementation: validated configuration, encrypted delegated device-code authentication, shared Microsoft HTTP client, Graph advanced-hunting client, connection-status and hunting tools, and bundled hunting-table reference.
- Streamable HTTP transport with tenant-scoped Entra bearer validation, protected-resource discovery metadata, request-scoped user identity, and in-memory Graph/MDE on-behalf-of token exchange.
- Read-only incident, alert, vulnerability, device, software and security-recommendation tools, with opaque continuation tokens and centrally shaped untrusted telemetry output.
- Production container deployment with a non-root runtime, read-only root filesystem, persistent audit volume and narrow version-only health endpoint.
- Ordered live-test runbook covering tenant authentication, every tool family, guardrails, HTTP authentication and the deferred Docker runtime gates.

### Changed

- Build spec correction pass (29/08/2026) after Codex pre-build review, verified by Claude: adopt MCP SDK v2 split packages (`@modelcontextprotocol/server`/`node`, protocol 2026-07-28) over the v1 monolith; SBOM via pnpm 11's native `pnpm sbom` (pnpm pinned via `packageManager`) replacing `@cyclonedx/cyclonedx-npm`; rate limiting upgraded to dual-window (per-minute + per-hour, retries consume capacity); HTTP auth decisions locked (Entra v2.0 tokens, `access_as_user` scope, no dynamic client registration); continuation tokens hardened against SSRF; `ina`/`aea` MDE regions added; MDE token audience pinned to `https://api.securitycenter.microsoft.com/.default`; audit log rotation + `0600` perms specified; coverage gate tooling added; Dockerfile pre-creates `/audit` for the non-root user; release artefact now includes the lockfile; step-ordering fixes (Step 2 gate, `obo.ts` reference) and an explicit phase↔step review map.

### Fixed

- HTTP requests now share one process-lifetime tenant rate limiter, continuation-token stores, and serialised audit writer instead of silently resetting those controls per SDK request factory invocation.
- OAuth discovery, bearer challenges, Host validation, and Origin validation now use the required explicit `DXM_PUBLIC_URL`; production URLs must use HTTPS.
- OBO token caching now sweeps expired entries and has a hard size bound; JWKS infrastructure failures surface as server verification outages rather than invalid-token errors.
- Nested KQL row operators can no longer prevent the outer result cap from being applied.
- KQL `adx()` calls are rejected alongside `externaldata` to prevent external data entering hunting results.
- Existing audit files are corrected to `0600` before append, pending audit writes are flushed during graceful transport shutdown, and audit code is included in the coverage gate.

<!--
Release template:

## [X.Y.Z] - DD/MM/YYYY
### Added / Changed / Fixed / Security / Deprecated / Removed
-->
