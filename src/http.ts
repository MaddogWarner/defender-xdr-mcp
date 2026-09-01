import { createServer as createNodeHttpServer, type Server as NodeHttpServer } from 'node:http';

import {
  createMcpHandler,
  requireBearerAuth,
  type AuthInfo,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import { toNodeHandler, type NodeIncomingMessageLike } from '@modelcontextprotocol/node';

import { authInfoUpn, EntraTokenVerifier } from './auth/bearer.js';
import type { AuthProvider } from './auth/msal.js';
import { createOnBehalfOfAuthFactory, type OnBehalfOfAuthFactory } from './auth/obo.js';
import type { AppConfig } from './config.js';
import type { RuntimeHandle } from './runtime.js';
import {
  createServer as createDefenderServer,
  createServerSharedState,
  SERVER_VERSION,
  type ServerSharedState,
} from './tools/registry.js';

const MCP_PATH = '/mcp';
const METADATA_PATH = '/.well-known/oauth-protected-resource';
const HEALTH_PATH = '/healthz';
const REQUIRED_SCOPE = 'access_as_user';

interface OboFactory {
  create(
    assertion: string,
    upn: string,
    inboundExpiresAt: number,
  ): AuthProvider & { prime(): Promise<void> };
}

interface FetchHandler {
  fetch(request: Request): Promise<Response>;
}

export function createHttpFetchHandler(
  config: AppConfig,
  verifier: OAuthTokenVerifier,
  oboFactory: OboFactory,
  sharedState: ServerSharedState = createServerSharedState(config),
): FetchHandler {
  const publicOrigin = configuredPublicOrigin(config);
  const mcp = createMcpHandler(async ({ authInfo }) => {
    if (authInfo?.expiresAt === undefined) {
      throw new Error('Validated HTTP authentication context is missing');
    }
    const auth = oboFactory.create(authInfo.token, authInfoUpn(authInfo), authInfo.expiresAt);
    await auth.prime();
    return createDefenderServer(config, auth, sharedState);
  });

  return {
    async fetch(request: Request): Promise<Response> {
      const requestUrl = new URL(request.url);
      if (requestUrl.pathname === HEALTH_PATH && requestUrl.search === '') {
        if (request.method !== 'GET') {
          return Response.json(
            { error: 'method_not_allowed' },
            { status: 405, headers: { Allow: 'GET' } },
          );
        }
        return Response.json(
          { version: SERVER_VERSION },
          { headers: { 'Cache-Control': 'no-store' } },
        );
      }
      if (requestUrl.host !== publicOrigin.host) {
        return forbiddenRequest('Invalid Host header');
      }
      if (requestUrl.pathname === METADATA_PATH) {
        if (request.method === 'OPTIONS') {
          return new Response(null, {
            status: 204,
            headers: { 'Access-Control-Allow-Origin': '*', Allow: 'GET, OPTIONS' },
          });
        }
        if (request.method !== 'GET') {
          return Response.json(
            { error: 'method_not_allowed' },
            { status: 405, headers: { Allow: 'GET, OPTIONS' } },
          );
        }
        return protectedResourceMetadata(config, publicOrigin, requestUrl);
      }
      if (requestUrl.pathname !== MCP_PATH) {
        return Response.json({ error: 'not_found' }, { status: 404 });
      }

      const originFailure = validateRequestOrigin(request, publicOrigin);
      if (originFailure !== undefined) {
        return originFailure;
      }

      const resourceMetadataUrl = new URL(METADATA_PATH, publicOrigin).toString();
      const gate = requireBearerAuth({
        verifier,
        requiredScopes: [REQUIRED_SCOPE],
        resourceMetadataUrl,
      });
      const auth: AuthInfo | Response = await gate(request);
      if (auth instanceof Response) {
        return auth;
      }
      return mcp.fetch(request, { authInfo: auth });
    },
  };
}

export async function startHttp(config: AppConfig): Promise<RuntimeHandle> {
  const verifier = new EntraTokenVerifier(config);
  const oboFactory: OnBehalfOfAuthFactory = await createOnBehalfOfAuthFactory(config);
  const sharedState = createServerSharedState(config);
  const fetchHandler = createHttpFetchHandler(config, verifier, oboFactory, sharedState);
  const nodeHandler = toNodeHandler(fetchHandler, {
    onerror: (error) => console.error(`MCP HTTP transport failed: ${error.message}`),
  });
  const server = createNodeHttpServer((request, response) => {
    void nodeHandler(request as NodeIncomingMessageLike, response);
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(config.httpPort, config.httpHost);
  });
  server.on('error', (error) => console.error(`MCP HTTP transport failed: ${error.message}`));
  console.error(
    `defender-xdr-mcp is listening on http://${config.httpHost}:${config.httpPort}${MCP_PATH}`,
  );
  return {
    close: async () => {
      try {
        await closeHttpServer(server);
      } finally {
        await sharedState.audit.flush();
      }
    },
  };
}

function closeHttpServer(server: NodeHttpServer): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  });
}

function protectedResourceMetadata(
  config: AppConfig,
  publicOrigin: URL,
  requestUrl: URL,
): Response {
  if (requestUrl.search !== '') {
    return Response.json({ error: 'not_found' }, { status: 404 });
  }
  return Response.json(
    {
      resource: new URL(MCP_PATH, publicOrigin).toString(),
      authorization_servers: [`https://login.microsoftonline.com/${config.tenantId}/v2.0`],
      scopes_supported: [`api://${config.clientId}/${REQUIRED_SCOPE}`],
      bearer_methods_supported: ['header'],
      resource_name: 'defender-xdr-mcp',
    },
    {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store',
      },
    },
  );
}

function validateRequestOrigin(request: Request, publicOrigin: URL): Response | undefined {
  const origin = request.headers.get('origin');
  if (origin === null) {
    return undefined;
  }
  try {
    if (new URL(origin).origin === publicOrigin.origin) {
      return undefined;
    }
  } catch {
    // Fall through to the deny response.
  }
  return forbiddenRequest('Invalid Origin header');
}

function forbiddenRequest(message: string): Response {
  return Response.json(
    {
      jsonrpc: '2.0',
      error: { code: -32_000, message },
      id: null,
    },
    { status: 403 },
  );
}

function configuredPublicOrigin(config: AppConfig): URL {
  if (config.publicUrl === undefined) {
    throw new Error('DXM_PUBLIC_URL is required for HTTP transport');
  }
  return new URL(config.publicUrl);
}
