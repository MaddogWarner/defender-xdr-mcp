import { serveStdio } from '@modelcontextprotocol/server/stdio';

import type { DeviceCodeAuth } from './auth/msal.js';
import type { AppConfig } from './config.js';
import { createServer, createServerSharedState } from './tools/registry.js';

export interface RuntimeHandle {
  close(): Promise<void>;
}

export async function authenticateStdio(auth: DeviceCodeAuth): Promise<void> {
  const graphToken = await auth.getToken('graph');
  console.error(
    `Authenticated to Microsoft Graph as ${graphToken.account?.username ?? 'unknown user'}`,
  );
  const mdeToken = await auth.getToken('mde');
  console.error(
    `Authenticated to Defender for Endpoint as ${mdeToken.account?.username ?? 'unknown user'}`,
  );
}

export async function startStdio(
  config: AppConfig,
  auth: DeviceCodeAuth,
  devAuthSmoke: boolean,
  serve: typeof serveStdio = serveStdio,
): Promise<RuntimeHandle> {
  if (devAuthSmoke) {
    await authenticateStdio(auth);
  }

  const sharedState = createServerSharedState(config);
  console.error('defender-xdr-mcp is listening on stdio');
  const transport = serve(() => createServer(config, auth, sharedState), {
    onerror: (error) => {
      console.error(`MCP stdio transport failed: ${error.message}`);
      process.exitCode = 1;
    },
  });
  return {
    close: async () => {
      try {
        await transport.close();
      } finally {
        await sharedState.audit.flush();
      }
    },
  };
}
