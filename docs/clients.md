# Connecting AI clients

All local (stdio) configs share the same shape: run `node /path/to/defender-xdr-mcp/dist/index.js` with `DXM_TENANT_ID` and `DXM_CLIENT_ID` in the environment. After connecting, call `get_connection_status` and watch the client's MCP log/console for any Graph or MDE device-code prompt (it's printed to stderr).

## Claude Code (CLI / VS Code extension)

```bash
claude mcp add defender-xdr \
  --env DXM_TENANT_ID=<tenant-guid> \
  --env DXM_CLIENT_ID=<client-id> \
  -- node /path/to/defender-xdr-mcp/dist/index.js
```

## Claude Desktop

`claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "defender-xdr": {
      "command": "node",
      "args": ["/path/to/defender-xdr-mcp/dist/index.js"],
      "env": {
        "DXM_TENANT_ID": "<tenant-guid>",
        "DXM_CLIENT_ID": "<client-id>"
      }
    }
  }
}
```

## VS Code (GitHub Copilot / MCP)

`.vscode/mcp.json` in your workspace (or user-level MCP settings):

```json
{
  "servers": {
    "defender-xdr": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/defender-xdr-mcp/dist/index.js"],
      "env": {
        "DXM_TENANT_ID": "<tenant-guid>",
        "DXM_CLIENT_ID": "<client-id>"
      }
    }
  }
}
```

## Codex CLI

`~/.codex/config.toml`:

```toml
[mcp_servers.defender-xdr]
command = "node"
args = ["/path/to/defender-xdr-mcp/dist/index.js"]

[mcp_servers.defender-xdr.env]
DXM_TENANT_ID = "<tenant-guid>"
DXM_CLIENT_ID = "<client-id>"
```

## Gemini CLI

`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "defender-xdr": {
      "command": "node",
      "args": ["/path/to/defender-xdr-mcp/dist/index.js"],
      "env": {
        "DXM_TENANT_ID": "<tenant-guid>",
        "DXM_CLIENT_ID": "<client-id>"
      }
    }
  }
}
```

## Remote (HTTP) clients

Clients that support streamable HTTP MCP servers (including the Claude apps via custom connectors) connect to your deployed instance's URL, e.g. `https://defender-mcp.example.internal/mcp`, and authenticate via your Entra tenant. See [http-deployment.md](http-deployment.md).

> Client config formats move fast — these snippets were current as at 29/08/2026. If a client rejects the config, check that client's current MCP docs; the command/args/env triple is the stable part.
