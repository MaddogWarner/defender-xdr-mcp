# Shared (HTTP) deployment guide

Run one instance for the team. Every request is still authenticated as an individual analyst — the server validates each user's Entra bearer token and exchanges it **on-behalf-of** that user for Graph/Defender tokens. No shared identity, no app-only access, Defender RBAC intact.

## Additional Entra configuration (on the same app registration)

1. **Expose an API:** set the Application ID URI (`api://<client-id>`) and add the scope `access_as_user` (admin-and-users consent). Then open **Manifest** and set `requestedAccessTokenVersion` to `2`. Entra-only registrations otherwise default to v1.0 access tokens; this server deliberately pins the v2.0 issuer, so every v1.0 token is rejected with HTTP 401 `invalid_token`.
2. **Client credential for OBO:** upload a certificate (preferred; PEM with cert + private key, referenced by `DXM_CLIENT_CERT_PATH`) or create a client secret. This credential only enables the on-behalf-of exchange — the app still holds zero application permissions.
3. **Client provisioning — no dynamic registration.** Entra doesn't support the OAuth dynamic client registration some MCP clients attempt, so each remote client is configured with the org's pre-registered client ID and uses authorisation-code + PKCE. Add each client's redirect URI to the app registration as you onboard it.

For each remote MCP client, configure:

- MCP server URL: `https://defender-mcp.example.internal/mcp`
- Authorisation server: `https://login.microsoftonline.com/<tenant-id>/v2.0`
- Client ID: the pre-registered client application ID
- Scope: `api://<client-id>/access_as_user`
- Grant: authorisation code with PKCE
- Redirect URI: the exact URI the client documents; add it to the Entra app registration before connection

The server publishes `/.well-known/oauth-protected-resource` for discovery. It intentionally publishes no dynamic-client-registration endpoint.

## Server configuration

`.env` (never committed; use a secret manager where you have one):

```bash
DXM_TENANT_ID=<tenant-guid>
DXM_CLIENT_ID=<client-id>
DXM_CLIENT_SECRET=<secret>        # or DXM_CLIENT_CERT_PATH=/certs/obo.pem
DXM_TRANSPORT=http
DXM_PUBLIC_URL=https://defender-mcp.example.internal
DXM_MDE_REGION=au                 # match your tenant's geo
DXM_AUDIT_LOG_PATH=/audit/audit.jsonl
```

```bash
docker compose up -d
```

The compose file publishes `127.0.0.1:3020` only, runs the container as non-root with a read-only rootfs, drops all capabilities, and persists the audit log to a named volume.

The container health check calls the unauthenticated bare path `GET /healthz` over loopback. A healthy v1.0.0 process returns only `{"version":"1.0.0"}`. Queries, subpaths and non-GET methods do not share this Host-check bypass.

## TLS reverse proxy

Terminate TLS in front and forward to loopback. Caddy example:

```
defender-mcp.example.internal {
    request_body {
        max_size 1MB
    }
    reverse_proxy 127.0.0.1:3020
}
```

Set `DXM_PUBLIC_URL` to the externally reachable HTTPS origin. OAuth discovery, bearer challenges, `Host` validation, and browser `Origin` validation all use this explicit value; proxy headers are not trusted to determine security boundaries. Caddy preserves the matching `Host` by default.

nginx example:

```nginx
server {
    listen 443 ssl;
    server_name defender-mcp.example.internal;

    ssl_certificate /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/private-key.pem;
    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:3020;
        proxy_set_header Host $host;
        proxy_buffering off;
    }
}
```

The server and MCP SDK do not impose a request-body size limit. Enforce the 1 MB limit at the reverse proxy to bound memory use from oversized requests before they reach Node.js.

The Node.js service deliberately serves plain HTTP only on its configured bind address; it does not terminate TLS. Keep the default loopback bind, restrict the public proxy to your management network or VPN, and do not expose port `3020` directly.

## Operational checklist

- [ ] TLS proxy in front; server bound to loopback.
- [ ] `DXM_PUBLIC_URL` exactly matches the proxy's public HTTPS origin and preserved `Host`.
- [ ] App manifest sets `requestedAccessTokenVersion` to `2`.
- [ ] OBO secret/cert in a secret manager, rotated per your policy.
- [ ] `audit.jsonl` shipped to your log platform (it's append-only JSONL — trivial to forward).
- [ ] Conditional Access applies to the app's sign-ins — verify your policies cover it.
- [ ] `get_connection_status` returns your tenant + the calling user for a test analyst.
- [ ] Confirm a user _without_ Defender roles gets empty/denied results (RBAC proof).
- [ ] Complete and retain the recording sheet in [live-test-runbook.md](live-test-runbook.md).
