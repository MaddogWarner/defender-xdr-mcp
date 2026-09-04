# Production live-test runbook

Use this runbook for the first production-tenant test of defender-xdr-mcp v1.1.0. Run the gates in order. Record each result in the sheet at the end; do not mark a gate passed unless the expected output was observed.

The stdio and tenant gates are for David's live session in the week commencing 01/09/2026. Gate 6a–6c are CI-verified; Gate 6d requires David's authorised Docker host and remains deferred.

## Pre-flight

Expected before proceeding:

- The Entra app is single-tenant and has exactly these eight **Delegated** permissions, with tenant admin consent granted:

  | API                | Permission                    |
  | ------------------ | ----------------------------- |
  | Microsoft Graph    | `ThreatHunting.Read.All`      |
  | Microsoft Graph    | `SecurityIncident.Read.All`   |
  | Microsoft Graph    | `SecurityAlert.Read.All`      |
  | Microsoft Graph    | `User.Read`                   |
  | WindowsDefenderATP | `Vulnerability.Read`          |
  | WindowsDefenderATP | `Machine.Read`                |
  | WindowsDefenderATP | `Software.Read`               |
  | WindowsDefenderATP | `SecurityRecommendation.Read` |

- No Application permissions or `.ReadWrite` permissions are present.
- **Authentication → Allow public client flows** is set to **Yes**.
- **For Gate 5 (HTTP): Manifest → `requestedAccessTokenVersion`** is set to **`2`**. Without it, Entra-only registrations issue v1.0 access tokens and the server returns HTTP 401 `invalid_token`; an `iss` claim beginning with `https://sts.windows.net/` identifies this mismatch. Set the manifest value to `2` and acquire a new token. Do not weaken issuer validation.
- The test analyst has the intended Defender roles and device-group access.
- Node.js 20 or later is installed. The repository dependencies and v1.1.0 build complete with:

  ```bash
  npx --yes pnpm@11.24.0 install --frozen-lockfile
  npx --yes pnpm@11.24.0 build
  ```

Set the two required values and lower the tenant-wide hunting rate for the first session:

```bash
export DXM_TENANT_ID="<tenant-guid>"
export DXM_CLIENT_ID="<client-id>"
export DXM_HUNTING_RPM="10"
export DXM_AUDIT_LOG_PATH="$(pwd)/audit.jsonl"
```

`DXM_HUNTING_RPM=10` is deliberate: the hunting quota is shared by the tenant, so a test run can throttle the Defender portal and other integrations. The audit log will be written to the displayed absolute path. From the first real call it can contain production hostnames, UPNs, device identifiers and patient-adjacent search terms in query text. Protect and retain it under the organisation's logging policy; never paste the whole file into an issue.

Record the test start time in AEST and the built version:

```bash
date
node -p "require('./package.json').version"
```

Expected version:

```text
1.1.0
```

## Gate 1 — delegated authentication and encrypted cache

Expected on the first run:

- One or two Microsoft device-code prompts appear, depending on cached consent.
- Both resource-specific success lines appear exactly as below, with `<UPN>` replaced by the analyst's UPN.
- The command exits with code 0 without printing a listener line.

```text
Authenticated to Microsoft Graph as <UPN>
Authenticated to Defender for Endpoint as <UPN>
```

Run the sign-in command against the built artefact:

```bash
node dist/index.js --sign-in
```

Complete the device-code prompt with the intended analyst identity, including MFA and Conditional Access. Confirm the command exits with code 0, then run it again.

Expected on the second run: the two lines above appear again, the command exits with code 0, and there is **no new device-code prompt** or listener line. This proves silent acquisition from the encrypted MSAL cache for both Graph and MDE. If either resource prompts again, record Gate 1 as failed and capture stderr without the device code itself.

## Gate 2 — stdio MCP and advanced hunting

Expected before testing:

- MCP Inspector connects to `node dist/index.js` over stdio.
- `get_connection_status` returns the configured tenant ID, the analyst UPN, non-empty `graph` and `mde` scope arrays, and rate-limiter state. It must not return a token.
- `run_hunting_query` with `DeviceInfo | take 5` returns no more than five rows inside the untrusted-telemetry delimiters.

Start MCP Inspector with the required environment available to its server process:

```bash
npx --yes @modelcontextprotocol/inspector node dist/index.js
```

In Inspector:

1. Connect using the stdio transport.
2. Call `get_connection_status` with `{}`.
3. Call `run_hunting_query` with:

   ```json
   { "query": "DeviceInfo | take 5", "timespan": "P1D" }
   ```

Treat an empty result as a possible RBAC or data-availability result, but the call itself must succeed. A sign-in pointer, malformed-response error or token disclosure fails the gate.

## Gate 3 — one call from every API family

Expected before testing:

- Graph incidents and alerts return a shaped result, even if the value array is empty.
- MDE vulnerability and device calls return a shaped result, even if the value array is empty.
- No call returns an unbounded Microsoft continuation URL; pagination is represented only by an opaque UUID token.

In the same Inspector session, call:

1. `list_incidents` with `{"top":5}`.
2. `get_incident` with `{"id":"<id-from-list_incidents>"}`.
3. `list_alerts` with `{"top":5}`.
4. `list_vulnerabilities` with `{"top":5}`.
5. `list_devices` with `{"top":5}`.
6. `get_device` with `{"id":"<id-from-list_devices>"}`.
7. `list_software` with `{"top":5}`.
8. `list_security_recommendations` with `{"top":5}`.

The first MDE calls exercise the separate Defender token audience. A typical mismatch presents as HTTP 403 with an authorisation-related Microsoft error. Confirm the app has the four WindowsDefenderATP delegated permissions with admin consent, then confirm the implementation is acquiring the MDE resource scope `https://api.securitycenter.microsoft.com/.default`. Do not add Application or write permissions as a workaround.

Microsoft does not document OData `$top` or `$filter` support for software, security recommendations or machine references. The expected result is a shaped response. An HTTP 400 that mentions a query option fails the relevant subtest; capture the compact Microsoft error so the unsupported option can be diagnosed.

## Gate 4 — guardrails observed against the tenant

Expected before testing:

- `externaldata` is rejected before a Microsoft query is sent.
- `adx()` is rejected before a Microsoft query is sent.
- A wide response is truncated with a notice stating rows returned versus total and how to narrow the query.
- `audit.jsonl` gains one JSON object per attempted tool call, including the rejected call. No result row content is logged.

First call `run_hunting_query` with:

```json
{
  "query": "externaldata(value:string)[h@\"https://example.invalid/data.csv\"]",
  "timespan": "P1D"
}
```

Expected error text begins:

```text
The externaldata operator is not allowed because it can retrieve data from external locations.
```

Then call `run_hunting_query` with:

```json
{ "query": "adx('cluster/database').Table | take 5", "timespan": "P1D" }
```

Expected error text begins:

```text
The adx() function is not allowed because it can retrieve data from an external Azure Data Explorer cluster.
```

For a predictable byte-cap exercise, stop Inspector, set a temporary small response cap, restart it, and run a deliberately wide query:

```bash
export DXM_MAX_RESPONSE_BYTES="1024"
npx --yes @modelcontextprotocol/inspector node dist/index.js
```

```json
{ "query": "DeviceProcessEvents | take 50", "timespan": "P1D" }
```

Expected notice format:

```text
Output truncated: returned <RETURNED> of <TOTAL> rows. Narrow the query with filters, a shorter timespan, or a smaller top/take value.
```

If the tenant has fewer rows than needed to exceed 1024 bytes, use another populated hunting table without widening the timespan beyond `P1D`. Restore the normal cap after the test:

```bash
unset DXM_MAX_RESPONSE_BYTES
```

Inspect audit metadata without exposing query contents on screen:

```bash
jq -c '{ts,upn,tool,rowCount,durationMs,status,error}' "$DXM_AUDIT_LOG_PATH"
stat -f '%Sp %N' "$DXM_AUDIT_LOG_PATH"
```

Expected file mode on macOS is `-rw-------`. Confirm there is one line for every call made in Gates 2–4, including the rejected `externaldata` call with `status:"error"`, and that no response records appear.

## Gate 5 — streamable HTTP and bearer rejection

Expected before testing:

- MCP Inspector connects to `https://<public-origin>/mcp` using an Entra dev token for `api://<client-id>/access_as_user`.
- Each invalid token case returns HTTP 401.
- Every 401 includes a `WWW-Authenticate` header containing `resource_metadata="https://<public-origin>/.well-known/oauth-protected-resource"`.

Complete the additional HTTP deployment setup in [http-deployment.md](http-deployment.md): expose `access_as_user`, configure each test client's redirect URI, place the OBO secret or certificate in the approved secret manager, set `DXM_PUBLIC_URL`, and terminate TLS at the reverse proxy. Never print or record bearer tokens.

Connect Inspector to `https://<public-origin>/mcp` and call `get_connection_status`. Confirm the returned UPN is the token subject and both downstream resources are active.

From a controlled terminal that does not log command history, exercise the endpoint with separately supplied short-lived test tokens:

```bash
read -r -s DXM_TEST_BEARER
curl --silent --show-error --dump-header - --output /dev/null \
  --request POST \
  --header "Authorization: Bearer ${DXM_TEST_BEARER}" \
  --header "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"live-gate","version":"1.0.0"}}}' \
  https://<public-origin>/mcp
unset DXM_TEST_BEARER
```

Run it once each with:

1. A validly issued token for the wrong audience, such as Microsoft Graph.
2. A token issued by a different controlled tenant.
3. An expired test token.

Prepare these test tokens through the organisation's approved development-token process before the session. If any case cannot be supplied without exposing a credential, record that subtest as blocked; do not weaken token validation or forge production credentials to complete it.

## Gate 6 — container runtime

**Status before testing: Gate 6a–6c passed in GitHub Actions on 04/09/2026 at 11:46 AEST ([CI evidence](https://github.com/MaddogWarner/defender-xdr-mcp/actions/runs/33826849251)). Gate 6d remains DEFERRED because Docker is not installed on David's Mac. Run 6d only on an authorised Docker-capable host; do not copy the private working tree to an unauthorised host.**

Expected before each command:

- The image builds successfully from the repository.
- The container starts with a read-only root filesystem and its Docker health status becomes `healthy`; `GET /healthz` returns only `{"version":"1.1.0"}`.
- `whoami` inside the container returns `node`.
- The `node` user can append an audit probe to the mounted `/audit` volume.

On the authorised Docker host:

```bash
docker build --tag defender-xdr-mcp:1.1.0 .
docker volume create defender-xdr-mcp-live-audit
docker run --detach \
  --name defender-xdr-mcp-live \
  --read-only \
  --tmpfs /tmp \
  --publish 127.0.0.1:3020:3020 \
  --env DXM_TENANT_ID=11111111-1111-4111-8111-111111111111 \
  --env DXM_CLIENT_ID=22222222-2222-4222-8222-222222222222 \
  --env DXM_CLIENT_SECRET=container-startup-probe-only \
  --env DXM_PUBLIC_URL=http://127.0.0.1:3020 \
  --env DXM_HTTP_HOST=0.0.0.0 \
  --env DXM_AUDIT_LOG_PATH=/audit/audit.jsonl \
  --mount source=defender-xdr-mcp-live-audit,target=/audit \
  defender-xdr-mcp:1.1.0
```

After the health start period:

```bash
docker inspect --format '{{.State.Health.Status}}' defender-xdr-mcp-live
curl --silent --show-error http://127.0.0.1:3020/healthz
docker exec defender-xdr-mcp-live whoami
docker exec defender-xdr-mcp-live node -e "require('node:fs').appendFileSync('/audit/audit.jsonl', JSON.stringify({probe:'docker-audit-write'})+'\\n', {encoding:'utf8',flag:'a',mode:0o600})"
docker exec defender-xdr-mcp-live stat -c '%A %U:%G %n' /audit/audit.jsonl
```

Expected outputs, in order:

```text
healthy
{"version":"1.1.0"}
node
-rw------- node:node /audit/audit.jsonl
```

Retain the build log and command outputs as evidence. After evidence capture, remove the disposable container and volume only if the host owner authorises cleanup.

## Recording sheet

Use `Pass`, `Fail` or `Blocked`; never use `Pass` for a partially executed gate.

| Gate                          | Result  | Date/time (AEST)      | Evidence reference | Tester/notes                                                    |
| ----------------------------- | ------- | --------------------- | ------------------ | --------------------------------------------------------------- |
| Pre-flight                    |         |                       |                    |                                                                 |
| 1 — auth and restart          |         |                       |                    |                                                                 |
| 2 — stdio and hunting         |         |                       |                    |                                                                 |
| 3 — Graph and MDE families    |         |                       |                    |                                                                 |
| 4 — guardrails and audit      |         |                       |                    |                                                                 |
| 5 — HTTP valid token          |         |                       |                    |                                                                 |
| 5a — wrong audience 401       |         |                       |                    |                                                                 |
| 5b — wrong issuer 401         |         |                       |                    |                                                                 |
| 5c — expired token 401        |         |                       |                    |                                                                 |
| 6a — Docker build             | Pass    | 04/09/2026 11:46 AEST | CI run 33826849251 | GitHub Actions                                                  |
| 6b — Docker run and health    | Pass    | 04/09/2026 11:46 AEST | CI run 33826849251 | GitHub Actions                                                  |
| 6c — container user is `node` | Pass    | 04/09/2026 11:46 AEST | CI run 33826849251 | GitHub Actions                                                  |
| 6d — mounted audit write      | Blocked |                       |                    | Docker unavailable locally; deferred to David's authorised host |

For every failure, capture only:

- the command or MCP tool name and sanitised arguments;
- relevant stderr lines, with device codes, tokens, tenant IDs, UPNs and hostnames redacted where the evidence leaves the approved environment;
- the single corresponding audit line, sanitised if exported;
- the compact Microsoft error object: `{code, message, retryable}`;
- HTTP status and `WWW-Authenticate` header for Gate 5;
- container build/runtime logs for Gate 6.

Do not capture access tokens, refresh tokens, OBO credentials, full query results or the complete production audit file.
