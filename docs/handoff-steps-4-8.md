# Handoff — Steps 4–8 (Claude → Codex, 29/08/2026)

Phase 1 is signed off. This document is the **delta** for the remaining build: changed operating conditions, items carried forward from review, and the deliverable David needs for live testing.

**`codex-plan.md` remains the authoritative build spec.** Steps 4–8 are already specified there in full — do not re-derive or restate them. This document changes _how_ those steps are verified and adds the review items that came out of the Phase 1 cycle. Where the two conflict, this document wins for process; `codex-plan.md` wins for scope.

---

## 1. What has changed

David is testing in his **production tenant next week**. Consequently:

- **Every live gate in Steps 4–8 is deferred** into a single test session. Codex builds Steps 4 → 8 continuously against the automated gate only.
- **No live gate may be recorded as passed by Codex.** Mark each one `DEFERRED — live session, David, w/c 01/09/2026` in the step status. Per standing standards: never claim a gate that did not run. This is the single most important rule in this handoff.
- Claude still reviews at each phase boundary (after Step 4, after Step 5, after Step 7, and a final pass after Step 8). Reviews are on the automated gate plus code — they do not wait on live results.
- Step 8's "walk the README end-to-end against the built artefact" becomes **write the runbook** (section 5). David executes it.

Everything else in `AGENTS.md` and `codex-plan.md` stands unchanged.

## 2. Order of work

Straight through `codex-plan.md`: **Step 4 → Step 5 → Step 6 → Step 7 → Step 8.** Do not reorder. Do not start Phase 6 (GitHub) — that remains David-gated and out of scope here.

Standard gate after every step:

```
npx --yes pnpm@11.24.0 lint && npx --yes pnpm@11.24.0 typecheck && npx --yes pnpm@11.24.0 test && npx --yes pnpm@11.24.0 build
```

Node 26 no longer bundles Corepack and the globally installed pnpm is v9 — the pinned `npx` form above is the only one that works on this machine.

## 3. Carried forward from Phase 1 review

These came out of the three review rounds and are **not** in `codex-plan.md`. Each has a named home.

### Into Step 4

**3.1 — Silent-acquirable vs interaction-required.** `hasUsableToken()` currently conflates "signed in" with "holds a fresh cached access token". `#results` is process-local, so after every server restart the first domain-tool call returns "Not signed in to Microsoft Graph" even when the encrypted MSAL cache holds a valid account and silent acquisition would have succeeded instantly. The message is also inaccurate — the user _is_ signed in. Same fault fires once a token comes within the 5-minute expiry skew mid-session.

Replace the check so it distinguishes:

- **silent-acquirable** (an account exists in the cache) → proceed transparently, no extra round trip;
- **interaction-required** (no account, or MSAL says interaction is needed) → fail fast with the existing model-readable pointer to the sign-in tool.

Build this **before** registering the MDE tools, because 3.2 extends it.

**3.2 — Resource-aware MDE activation.** Already recorded at `codex-plan.md:126`. The MDE resource needs its own consent and its own token audience (`https://api.securitycenter.microsoft.com/.default`), so a user signed in to Graph is _not_ automatically signed in to MDE. The explicit sign-in tool must activate both resources, and MDE tools must fail fast the same way rather than launching a device-code flow inside a query. Report both resources separately in `get_connection_status`.

**3.3 — One-shot 401 invalidation.** Also at `codex-plan.md:126`. The in-memory token cache has no invalidation path: a revoked token or a Conditional Access policy change mid-session produces 401s until natural expiry. On a 401, invalidate the relevant cached token and perform **at most one** silent-first reacquisition and retry. A second 401 returns without further retry. Unit-test both the single-retry success and the repeated-401 path.

**3.4 — Continuation-token SSRF hardening is a hard requirement, not a nice-to-have.** `codex-plan.md:130` specifies it; call it out explicitly at review. Server-issued opaque IDs, bounded LRU, TTL ≤ 10 min, never accept a URL from the client, and re-validate the stored URL's host against the configured Graph/MDE origins on redemption. The existing `#resolvePath` host check in `clients/http.ts` is the model to follow.

### Into Step 5

**3.5 — Audit must actually fail closed.** The Phase 1 seam is `() => Promise.resolve()`. Step 5 replaces it with real JSONL persistence, and a tool call whose audit write fails must **fail the tool call**. Test the failure path explicitly (read-only directory, full disk simulation) — a fail-closed design that has never been observed failing is an assumption, not a control.

**3.6 — Audit error codes are already differentiated.** `pipeline.ts` emits `validation_error` (validator threw) and `validation_failed` (validator returned `{ok:false}`). Preserve that distinction when the real validator lands; do not collapse them.

**3.7 — Truncation metadata is plumbed but unused.** `ShapedToolOutput` already carries `rowCount`, `totalRows`, `truncated` and `notices`, and every tool currently reports `truncated: false`. The output shaper must populate these honestly, and the truncation notice must state rows returned vs total and how to narrow the query.

**3.8 — Remove the Phase 1 shaping duplication.** `shapeHuntingResult` in `tools/hunting.ts` hand-rolls the untrusted-telemetry delimiters. Step 5's shaper owns that wrapper for every tool — delete the local copy rather than leaving two implementations to drift.

### Into Step 7

**3.9 — Corepack in the Dockerfile.** `Dockerfile:4` still runs `corepack enable`. It works on `node:24-alpine` but Corepack is unbundled from Node 25+, so the base-image bump will break it silently. Switch to the pinned `npx --yes pnpm@11.24.0` form used everywhere else, or install pnpm explicitly. Verify `dist/index.js` is the entry — the build layout was fixed during Phase 1 and `CMD` was corrected with it, but re-confirm after any tsconfig change.

### Into Step 8

**3.10 — CHANGELOG.** Remove the ⚠ pre-guardrail Security block once Step 5 is complete and reviewed — it is a build-state warning, not a release note. Move `[Unreleased]` → `[1.0.0]` with the date per Keep a Changelog.

**3.11 — Doc consistency sweep.** README, `docs/clients.md`, `docs/http-deployment.md` and `AGENTS.md` all currently describe the finished v1. Once the build is complete, verify every command, path and config key against the built artefact. Particular attention to the entry path (`dist/index.js`) and the pnpm invocation form, both of which drifted during Phase 1.

## 4. Standing rules (unchanged, restated because they bind every step)

- **Read-only forever.** No write or response-action endpoint, no application permissions, no scope beyond those named in `codex-plan.md`. Adding any scope = stop and escalate.
- **Nothing pushed, tagged, released or published.** Phase 6 is David-gated. This applies through Step 8 inclusive.
- TypeScript strict; no `any` without a justifying comment. Lint and format must pass.
- Never log or persist tokens or secrets. Audit carries metadata and query text, never result rows.
- Validate at every boundary with zod: config, tool inputs, Microsoft responses.
- No live network calls in unit tests.
- stdout is the MCP wire in stdio mode; everything human-facing goes to stderr.
- Guardrail coverage gate from Step 5 onward: ≥90 % lines on `src/guardrails/**`, enforced by vitest thresholds.

## 5. Deliverable for the live session — `docs/live-test-runbook.md`

Produce this as part of Step 8. It is what David executes in production next week, so it must be runnable by someone who has not read the codebase. Required content:

1. **Pre-flight.** App registration checklist (the eight delegated permissions, "Allow public client flows", admin consent), the two required env vars, and a **recommended `DXM_HUNTING_RPM=10` for the first session** — hunting quota is tenant-wide and a test run can throttle the Defender portal and other integrations. State where the audit log will be written and that it will contain real hostnames and UPNs from the first query.
2. **Gate 1 (Step 2) — auth.** Device-code sign-in succeeds for Graph _and_ MDE; restart the process and confirm silent re-acquisition with no second prompt. Expected stderr lines quoted verbatim.
3. **Gate 2 (Step 3) — stdio.** MCP Inspector connects; `get_connection_status` returns tenant, UPN and per-resource scopes; `DeviceInfo | take 5` returns rows.
4. **Gate 3 (Step 4) — one tool per family.** One Graph incidents/alerts call, one MDE vulnerabilities/devices call. This is the first real exercise of the MDE token audience — if anything is going to 403, it is this. Include the audience-mismatch symptom and remedy.
5. **Gate 4 (Step 5) — guardrails observed live.** A query with `externaldata` is rejected; an oversized result truncates with a notice; an audit line appears for every call including the rejected one.
6. **Gate 5 (Step 6) — HTTP.** Inspector connects over HTTP with a dev token; a bad audience/issuer/expiry returns 401 with `WWW-Authenticate`.
7. **Gate 6 (Step 7) — container.** Docker is not installed on David's Mac — state that plainly and mark it deferred to a Docker-capable host or CI. Do not write it as though it will run.
8. **Recording sheet.** A pass/fail/blocked table David fills in, plus what to capture on failure (stderr, the audit line, the compact `{code, message, retryable}` error) so a failure is diagnosable without a second production run.

Every expected output must be stated _before_ the step, so a deviation is obvious rather than something to rationalise afterwards.

## 6. Definition of done

- Steps 4–8 complete in `codex-plan.md`, each with an honest status line.
- Automated gate green at every step; `test:coverage` green from Step 5.
- Every item in section 3 addressed, or explicitly raised to Claude with a reason if not.
- `docs/live-test-runbook.md` written.
- Every live gate marked `DEFERRED`, never passed.
- Handed to Claude for phase reviews at the Step 4, 5, 7 and 8 boundaries.
- Nothing pushed, tagged or released.
