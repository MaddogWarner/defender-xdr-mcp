import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';

import type { AuthProvider } from '../auth/msal.js';
import type { RequestRateLimiter } from '../clients/http.js';
import type { AppConfig } from '../config.js';
import type { ToolPipeline } from './pipeline.js';

export async function getAuthenticatedConnectionStatus(
  config: Pick<AppConfig, 'tenantId'>,
  auth: Pick<AuthProvider, 'getToken' | 'getConnectionStatus'>,
  rateLimiter: RequestRateLimiter,
) {
  await auth.getToken('graph');
  await auth.getToken('mde');
  return {
    tenantId: config.tenantId,
    ...auth.getConnectionStatus(),
    rateLimiter: rateLimiter.state(),
  };
}

export function registerMetaTools(
  server: McpServer,
  config: AppConfig,
  auth: AuthProvider,
  rateLimiter: RequestRateLimiter,
  pipeline: ToolPipeline,
): void {
  server.registerTool(
    'get_connection_status',
    {
      description:
        'Explicitly activate Microsoft Graph and Defender for Endpoint, then return the tenant, signed-in user, per-resource granted scopes, and local request-budget state. Never returns access or refresh tokens.',
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async () => {
      const outcome = await pipeline.run({
        tool: 'get_connection_status',
        args: {},
        input: undefined,
        validate: () => ({ ok: true, value: undefined, notices: [] }),
        execute: () => getAuthenticatedConnectionStatus(config, auth, rateLimiter),
      });
      if (!outcome.ok) {
        return { content: [{ type: 'text', text: outcome.reason }], isError: true };
      }
      return { content: [{ type: 'text', text: outcome.output.text }] };
    },
  );
}
