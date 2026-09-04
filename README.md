# defender-xdr-mcp

**A self-hosted, strictly read-only [MCP](https://modelcontextprotocol.io) server for Microsoft Defender XDR.**

Bring your own AI to your Defender telemetry. If your org runs Microsoft 365 E5 (or the equivalent Defender licences) but doesn't run Sentinel, this server lets your analysts connect the AI tooling they already use — Claude, Claude Code, VS Code, Codex CLI, Gemini CLI — directly to Defender XDR for AI-assisted threat hunting, incident triage, and vulnerability discovery.

- **Strictly read-only.** The Entra app registration only ever holds read scopes. There is no code path that can isolate a device, modify an alert, or change anything in your tenant — and no roadmap to add one.
- **Your users, your RBAC.** Delegated authentication only. Every query runs as the signed-in analyst, so existing Defender roles, device-group scoping, and Entra sign-in audit apply unchanged. The server holds no standing tenant-wide credential.
- **Production guardrails.** KQL validation, client-side rate limiting tuned below Microsoft's API quotas, response size caps, and an append-only audit log of every tool call.
- **Self-hosted.** Runs locally next to your editor (stdio) or as a shared service for the team (streamable HTTP + Docker). **The server itself** sends your telemetry nowhere except your own tenant's Microsoft endpoints — no vendor backend, no analytics, no third-party service in the data path.

> **Read this before you deploy — where your data actually goes.** This server does not transmit telemetry to any third party. Your **AI client** does. The entire purpose of an MCP server is to feed tool results to a model, so whatever Defender data a tool returns is sent by your AI client to whichever model provider it uses (Anthropic, OpenAI, Google, or a model you host yourself). Self-hosting this server removes one hop, not that one. Assess the AI client and its provider as part of the same decision — see [`docs/security-assessment.md`](docs/security-assessment.md), risk **R1**.
>
> **Verification status (04/09/2026).** v1.1.0 has passed lint, strict typecheck, 166 unit tests, 98.96 % line coverage across guardrails and audit, and CI container build/start/health/non-root checks. It **has never been run against a live Microsoft 365 tenant**, and the mounted-volume audit-write check remains deferred. Those gates are documented in [`docs/live-test-runbook.md`](docs/live-test-runbook.md). Treat this as pre-production software until that runbook is completed and signed off.
>
> **Disclaimer:** this is an independent open-source project. It is not affiliated with, endorsed by, or supported by Microsoft. "Microsoft Defender" is a trademark of Microsoft Corporation.

---

## How it works

```
Claude / Claude Code / VS Code / Codex / Gemini
        │  stdio (local)  ─or─  streamable HTTP (shared, Entra OAuth)
        ▼
defender-xdr-mcp  ──  KQL validator → rate limiter → output shaper → audit log
        │
        ├── Microsoft Graph security API   (advanced hunting, incidents, alerts)
        └── Defender for Endpoint API      (vulnerabilities, devices, software)
```

The server signs the analyst in with their own Entra ID identity (device-code flow locally; OAuth on-behalf-of in HTTP mode) and exposes Defender XDR data as MCP tools the AI client can call.

## Tools

| Tool                              | What it does                                                                                                                                 |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `run_hunting_query`               | Run KQL against the advanced hunting tables (30-day window). Guardrailed: timespan capped, row-limited, `externaldata` and `adx()` rejected. |
| `list_hunting_tables`             | Bundled schema reference for the advanced hunting tables — lets the AI write correct KQL without trial-and-error.                            |
| `list_incidents` / `get_incident` | Browse and read incidents (filter by status, severity, assignment, time); incident detail includes correlated alerts.                        |
| `list_alerts` / `get_alert`       | Browse and read alerts with evidence.                                                                                                        |
| `list_vulnerabilities`            | Org-wide CVEs from Defender Vulnerability Management (filter by severity or CVE ID; returned exploit and EPSS fields support analysis).      |
| `list_vulnerable_devices`         | Devices exposed to a given CVE.                                                                                                              |
| `list_devices` / `get_device`     | Device inventory (filter by risk score, exposure level, OS); device detail includes its discovered vulnerabilities.                          |
| `list_software`                   | Software inventory with weaknesses and exposure.                                                                                             |
| `list_security_recommendations`   | Defender's prioritised remediation recommendations.                                                                                          |
| `get_connection_status`           | In-session Graph and MDE status/reactivation tool; returns tenant, signed-in user, per-resource scopes, and rate-limiter state.              |

## Prerequisites

- Microsoft 365 E5, or licences covering Defender for Endpoint P2 / Defender XDR with advanced hunting and Defender Vulnerability Management.
- Rights to create an Entra ID app registration (or a friendly Entra admin).
- Analysts need appropriate Defender roles (e.g. Security Reader plus device-group access) — the server can't show a user anything Defender itself wouldn't.
- Node.js ≥ 20 (local mode) or Docker (shared mode).

## Setup

### 1. Create the Entra app registration

One registration per org, created once by an admin:

1. **Entra admin centre → App registrations → New registration.** Name it (e.g. `defender-xdr-mcp`), single tenant, no redirect URI needed for local use.
2. **Authentication → Advanced settings → Allow public client flows → Yes** (required for device-code sign-in).
3. **API permissions → Add a permission**, then add these **Delegated** permissions:

   | API                | Delegated permission          | Used for           |
   | ------------------ | ----------------------------- | ------------------ |
   | Microsoft Graph    | `ThreatHunting.Read.All`      | Advanced hunting   |
   | Microsoft Graph    | `SecurityIncident.Read.All`   | Incidents          |
   | Microsoft Graph    | `SecurityAlert.Read.All`      | Alerts             |
   | Microsoft Graph    | `User.Read`                   | Sign-in / identity |
   | WindowsDefenderATP | `Vulnerability.Read`          | Vulnerability data |
   | WindowsDefenderATP | `Machine.Read`                | Device inventory   |
   | WindowsDefenderATP | `Software.Read`               | Software inventory |
   | WindowsDefenderATP | `SecurityRecommendation.Read` | Recommendations    |

   (The Defender for Endpoint API appears as **WindowsDefenderATP** in the permission picker. **Do not add any Application permissions, and nothing ending in `.ReadWrite` — read-only is the point.**)

4. **Grant admin consent** for the tenant.
5. Note the **Application (client) ID** and **Directory (tenant) ID**.

### 2. Run the server (local / stdio)

```bash
git clone https://github.com/MaddogWarner/defender-xdr-mcp.git
cd defender-xdr-mcp
npx --yes pnpm@11.24.0 install
npx --yes pnpm@11.24.0 build
```

Set the two required values (env vars or a `.env` you keep out of git):

```bash
export DXM_TENANT_ID="<your-tenant-guid>"
export DXM_CLIENT_ID="<your-app-client-id>"
```

Before connecting the client, authenticate once from the built artefact:

```bash
node dist/index.js --sign-in
```

Complete any Graph and MDE device-code prompts with your normal work account; MFA and Conditional Access apply as usual. The command exits after both resources authenticate, and tokens are cached encrypted via your OS keystore. After connecting, use `get_connection_status` for in-session status or reactivation.

### 3. Connect your AI client

**Claude Code:**

```bash
claude mcp add defender-xdr --env DXM_TENANT_ID=<tenant> --env DXM_CLIENT_ID=<client> -- node /path/to/defender-xdr-mcp/dist/index.js
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "defender-xdr": {
      "command": "node",
      "args": ["/path/to/defender-xdr-mcp/dist/index.js"],
      "env": { "DXM_TENANT_ID": "<tenant>", "DXM_CLIENT_ID": "<client>" }
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`), **Codex CLI** (`~/.codex/config.toml` `[mcp_servers.defender-xdr]`), and **Gemini CLI** (`~/.gemini/settings.json` `mcpServers`) use the same command/args/env shape — see [docs/clients.md](docs/clients.md) for exact snippets.

### 4. Shared deployment (HTTP + Docker) — optional

For a team-wide instance, run the streamable HTTP transport behind TLS. In this mode the server validates each user's Entra bearer token and exchanges it on-behalf-of the user for Graph/Defender tokens — still per-user, still read-only, no shared identity. Requires a client secret or certificate on the app registration (for the OBO exchange only) and an exposed API scope. Full walkthrough incl. reverse-proxy TLS examples: [docs/http-deployment.md](docs/http-deployment.md).

```bash
docker compose up -d
```

The container runs as non-root with a read-only filesystem and binds loopback by default — fronting it with your TLS proxy is deliberate, not optional.

Before production rollout, execute the ordered tenant and container checks in the [live test runbook](docs/live-test-runbook.md) and retain its completed recording sheet with the deployment evidence.

## Assessing this before you deploy it

If you need to put this through a security or risk assessment, start with **[docs/security-assessment.md](docs/security-assessment.md)**. It carries the architecture and trust boundaries, a data inventory and classification, the control inventory with file-level citations, an honest statement of what has and has not been tested, the supply-chain position, a pre-filled risk register, and Essential Eight / NSW Cyber Security Policy alignment.

| Document                                                   | Use it for                                                    |
| ---------------------------------------------------------- | ------------------------------------------------------------- |
| [docs/security-assessment.md](docs/security-assessment.md) | Risk assessment evidence pack and risk register               |
| [SECURITY.md](SECURITY.md)                                 | Threat model, read-only guarantee, hardening, reporting a bug |
| [docs/live-test-runbook.md](docs/live-test-runbook.md)     | The outstanding verification gates                            |
| [docs/http-deployment.md](docs/http-deployment.md)         | Shared-mode deployment and TLS                                |
| [docs/api-verification.md](docs/api-verification.md)       | Microsoft endpoints, scopes and quotas as verified            |
| [docs/clients.md](docs/clients.md)                         | AI client configuration                                       |

## Configuration reference

| Env var                                      | Default              | Purpose                                                                                                                      |
| -------------------------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `DXM_TENANT_ID`                              | _(required)_         | Entra tenant GUID                                                                                                            |
| `DXM_CLIENT_ID`                              | _(required)_         | App registration client ID                                                                                                   |
| `DXM_TRANSPORT`                              | `stdio`              | `stdio` or `http`                                                                                                            |
| `DXM_MDE_REGION`                             | global               | `au`/`us`/`eu`/`uk`/`swa`/`ina`/`aea` — regional Defender API endpoint                                                       |
| `DXM_DEFAULT_TIMESPAN`                       | `P7D`                | Hunting timespan when the query doesn't set one                                                                              |
| `DXM_MAX_TIMESPAN`                           | `P30D`               | Hard hunting timespan cap                                                                                                    |
| `DXM_MAX_ROWS`                               | `1000`               | Max rows returned to the AI per call; Microsoft Graph list endpoints may impose a lower page-size maximum                    |
| `DXM_MAX_RESPONSE_BYTES`                     | `262144`             | Max serialised response size; hard ceiling `50000000`                                                                        |
| `DXM_HUNTING_RPM` / `DXM_HUNTING_RPH`        | `40` / `1200`        | Per-process Graph budget for hunting, incidents and alerts; Microsoft's hunting cap is approximately 45/min per tenant       |
| `DXM_MDE_RPM` / `DXM_MDE_RPH`                | `45` / `1350`        | Defender API rate limits (Microsoft's caps ≈ 50/min, 1,500/hr)                                                               |
| `DXM_AUDIT_LOG_PATH`                         | `./audit.jsonl`      | Append-only audit log location                                                                                               |
| `DXM_AUDIT_MAX_MB` / `DXM_AUDIT_KEEP`        | `256` / `5`          | Audit log rotation: size threshold and rotated files kept                                                                    |
| `DXM_HTTP_HOST` / `DXM_HTTP_PORT`            | `127.0.0.1` / `3020` | HTTP mode bind                                                                                                               |
| `DXM_PUBLIC_URL`                             | _(HTTP required)_    | Public HTTPS origin used for OAuth discovery and Host/Origin validation; loopback HTTP is allowed only for local development |
| `DXM_CLIENT_SECRET` / `DXM_CLIENT_CERT_PATH` | —                    | HTTP mode only, for the OBO exchange                                                                                         |

Microsoft's hunting quota is tenant-wide, while local stdio limiting is per server process. As a starting point, set each analyst's `DXM_HUNTING_RPM` below `45 ÷ concurrent stdio analysts` and leave headroom for the Defender portal and other integrations. HTTP mode uses one shared process-wide budget. Incidents and alerts consume the same `DXM_HUNTING_*` budget. Microsoft Graph list endpoints also enforce their own page-size maximums; a `DXM_MAX_ROWS` value above an endpoint's limit can produce HTTP 400 rather than a larger page.

## Security model, in brief

- **Least privilege:** delegated read scopes only; Defender RBAC decides what each user sees; no app-only access exists.
- **Quota safety:** client-side token buckets sit below Microsoft's published limits (advanced hunting ≈ 45 calls/min and CPU-time quotas per tenant), with `Retry-After` honoured — one enthusiastic agent can't starve your SOC's API quota.
- **Bounded output:** row and byte caps with explicit truncation notices stop bulk telemetry extraction and keep the AI's context intact.
- **Audit:** every tool call is appended to a local JSONL log — timestamp, user, tool, query text, row count, status. Result content is never logged.
- **Audit-log sensitivity:** query text can contain hostnames, UPNs, device identifiers, or patient-adjacent search terms. Restrict access to the log and apply your organisation's healthcare-data retention, forwarding, and disposal policy.
- **Prompt-injection posture:** telemetry fields (alert titles, file names, email subjects) can be attacker-influenced. Results are returned as clearly delimited untrusted data, and KQL routes to external data (`externaldata` and `adx()`) are rejected. Your AI harness should treat Defender output as data, not instructions — see [SECURITY.md](SECURITY.md).

## Troubleshooting

- **Sign-in required:** run `node dist/index.js --sign-in` in a terminal before connecting the client. Use `get_connection_status` for in-session status or reactivation.
- _AADSTS65001 / consent errors:_ admin consent not granted, or a scope is missing from the app registration.
- _Empty hunting results but no error:_ check the user's Defender role and device-group access — RBAC applies server-side at Microsoft.
- _429s despite the limiter:_ the Microsoft hunting quota is tenant-wide but stdio limits are per process. Set each analyst's `DXM_HUNTING_RPM` below `45 ÷ concurrent analysts`, leave portal headroom, and remember incidents and alerts use the same budget. HTTP mode already shares one process-wide budget.
- _HTTP 400 after raising `DXM_MAX_ROWS`:_ Microsoft Graph list endpoints impose their own page-size maximums. Lower `DXM_MAX_ROWS` or the tool's `top` value.

## Contributing & licence

Issues and PRs welcome. Read [SECURITY.md](SECURITY.md) for vulnerability reporting (please don't open public issues for security bugs). Licensed [MIT](LICENSE).

API surface verified against Microsoft Learn on 29/08/2026. Microsoft's legacy advanced-hunting and alerts APIs retire on 01/02/2027 and 15/10/2026 respectively; this project targets their Graph replacements.
