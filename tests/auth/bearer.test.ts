import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWTVerifyGetKey,
} from 'jose';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { EntraTokenVerifier } from '../../src/auth/bearer.js';
import type { AuthProvider } from '../../src/auth/msal.js';
import { ContinuationTokenStore } from '../../src/clients/continuationTokens.js';
import { loadConfig, type AppConfig } from '../../src/config.js';
import { DualWindowRateLimiter } from '../../src/guardrails/rateLimiter.js';
import { createHttpFetchHandler } from '../../src/http.js';
import type { ServerSharedState } from '../../src/tools/registry.js';

const TENANT_ID = '11111111-1111-4111-8111-111111111111';
const CLIENT_ID = '22222222-2222-4222-8222-222222222222';
const ISSUER = `https://login.microsoftonline.com/${TENANT_ID}/v2.0`;
const KID = 'test-key';

let signingKey: CryptoKey;
let wrongSigningKey: CryptoKey;
let getKey: JWTVerifyGetKey;
let config: AppConfig;

beforeAll(async () => {
  const keyPair = await generateKeyPair('RS256');
  const wrongKeyPair = await generateKeyPair('RS256');
  signingKey = keyPair.privateKey;
  wrongSigningKey = wrongKeyPair.privateKey;
  const jwk = await exportJWK(keyPair.publicKey);
  getKey = createLocalJWKSet({ keys: [{ ...jwk, kid: KID, alg: 'RS256', use: 'sig' }] });
  config = loadConfig({
    DXM_TENANT_ID: TENANT_ID,
    DXM_CLIENT_ID: CLIENT_ID,
    DXM_TRANSPORT: 'http',
    DXM_CLIENT_SECRET: 'test-client-secret',
    DXM_PUBLIC_URL: 'https://defender.example',
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function token(
  overrides: {
    audience?: string;
    issuer?: string;
    expiry?: number;
    notBefore?: number;
    scopes?: string;
    key?: CryptoKey;
  } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    tid: TENANT_ID,
    preferred_username: 'analyst@example.com',
    oid: '33333333-3333-4333-8333-333333333333',
    scp: overrides.scopes ?? 'access_as_user',
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(overrides.issuer ?? ISSUER)
    .setAudience(overrides.audience ?? `api://${CLIENT_ID}`)
    .setIssuedAt(now)
    .setNotBefore(overrides.notBefore ?? now - 1)
    .setExpirationTime(overrides.expiry ?? now + 3600)
    .sign(overrides.key ?? signingKey);
}

function handler() {
  const verifier = new EntraTokenVerifier(config, getKey);
  const create = vi.fn(() => {
    throw new Error('OBO must not run for an invalid bearer token');
  });
  const http = createHttpFetchHandler(config, verifier, { create });
  return { fetch: (request: Request) => http.fetch(request), create };
}

function authenticatedProvider(): AuthProvider & { prime(): Promise<void> } {
  const downstreamToken = {
    accessToken: 'downstream-token',
    grantedScopes: ['Test.Read'],
    expiresOn: new Date(Date.now() + 3600_000),
  };
  return {
    prime: () => Promise.resolve(),
    getToken: () => Promise.resolve(downstreamToken),
    getTokenSilently: () => Promise.resolve(downstreamToken),
    invalidate: vi.fn(),
    hasUsableToken: () => Promise.resolve(true),
    getConnectionStatus: () => ({
      upn: 'analyst@example.com',
      scopes: { graph: ['Test.Read'], mde: ['Test.Read'] },
    }),
  };
}

function sharedState(
  append: ServerSharedState['audit']['append'] = vi.fn(() => Promise.resolve()),
): ServerSharedState {
  return {
    rateLimiter: new DualWindowRateLimiter({
      hunting: { requestsPerMinute: 40, requestsPerHour: 1200 },
      'graph-other': { requestsPerMinute: 40, requestsPerHour: 1200 },
      mde: { requestsPerMinute: 45, requestsPerHour: 1350 },
    }),
    graphContinuationTokens: new ContinuationTokenStore(['https://graph.microsoft.com']),
    mdeContinuationTokens: new ContinuationTokenStore(['https://api.security.microsoft.com']),
    audit: { append, flush: vi.fn(() => Promise.resolve()) },
  };
}

function toolRequest(bearer: string, id: number, argumentsValue: Record<string, unknown> = {}) {
  return new Request('http://defender.example/mcp', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      Accept: 'application/json, text/event-stream',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id,
      method: 'tools/call',
      params: { name: 'list_incidents', arguments: argumentsValue },
    }),
  });
}

describe('HTTP Entra bearer validation', () => {
  const invalidTokenCases: Array<[string, () => Promise<string>]> = [
    ['wrong audience', () => token({ audience: 'api://wrong-audience' })],
    ['wrong issuer', () => token({ issuer: 'https://login.microsoftonline.com/common/v2.0' })],
    ['expired token', () => token({ expiry: Math.floor(Date.now() / 1000) - 1 })],
    ['future nbf', () => token({ notBefore: Math.floor(Date.now() / 1000) + 600 })],
    ['wrong signature', () => token({ key: wrongSigningKey })],
    ['missing scope', () => token({ scopes: 'unrelated_scope' })],
  ];

  it.each(invalidTokenCases)('returns a discoverable 401 for a %s', async (_label, makeToken) => {
    const current = handler();
    const response = await current.fetch(
      new Request('http://defender.example/mcp', {
        method: 'POST',
        headers: { Authorization: `Bearer ${await makeToken()}` },
      }),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain(
      'resource_metadata="https://defender.example/.well-known/oauth-protected-resource"',
    );
    expect(current.create).not.toHaveBeenCalled();
  });

  it('accepts both configured Entra audience forms and exposes only validated identity metadata', async () => {
    const verifier = new EntraTokenVerifier(config, getKey);

    for (const audience of [CLIENT_ID, `api://${CLIENT_ID}`]) {
      const bearer = await token({ audience });
      const authInfo = await verifier.verifyAccessToken(bearer);

      expect(authInfo.clientId).toBe(CLIENT_ID);
      expect(authInfo.extra?.upn).toBe('analyst@example.com');
      expect(authInfo.expiresAt).toEqual(expect.any(Number));
    }
  });

  it('passes validated identity into OBO and serves an MCP initialise request', async () => {
    const bearer = await token();
    const downstreamToken = {
      accessToken: 'downstream-token',
      grantedScopes: ['Test.Read'],
      expiresOn: new Date(Date.now() + 3600_000),
    };
    const prime = vi.fn(() => Promise.resolve());
    const auth: AuthProvider & { prime(): Promise<void> } = {
      prime,
      getToken: vi.fn(() => Promise.resolve(downstreamToken)),
      getTokenSilently: vi.fn(() => Promise.resolve(downstreamToken)),
      invalidate: vi.fn(),
      hasUsableToken: vi.fn(() => Promise.resolve(true)),
      getConnectionStatus: () => ({
        upn: 'analyst@example.com',
        scopes: { graph: ['Test.Read'], mde: ['Test.Read'] },
      }),
    };
    const create = vi.fn(() => auth);
    const http = createHttpFetchHandler(config, new EntraTokenVerifier(config, getKey), {
      create,
    });
    const response = await http.fetch(
      new Request('http://defender.example/mcp', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${bearer}`,
          Accept: 'application/json, text/event-stream',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-11-25',
            capabilities: {},
            clientInfo: { name: 'vitest', version: '1.0.0' },
          },
        }),
      }),
    );

    expect(response.status).toBe(200);
    expect(create).toHaveBeenCalledWith(bearer, 'analyst@example.com', expect.any(Number));
    expect(prime).toHaveBeenCalledOnce();
    await expect(response.text()).resolves.toContain('"name":"defender-xdr-mcp"');
  });

  it('serves protected-resource metadata without authentication', async () => {
    const response = await handler().fetch(
      new Request('http://defender.example/.well-known/oauth-protected-resource'),
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      resource: 'https://defender.example/mcp',
      authorization_servers: [ISSUER],
      scopes_supported: [`api://${CLIENT_ID}/access_as_user`],
    });
  });

  it('serves only the version from the unauthenticated health endpoint', async () => {
    const current = handler();
    const response = await current.fetch(new Request('http://127.0.0.1:3020/healthz'));

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    await expect(response.json()).resolves.toEqual({ version: '1.0.0' });
    expect(current.create).not.toHaveBeenCalled();
  });

  it('does not treat health subpaths, queries, or non-GET methods as healthy', async () => {
    const current = handler();
    const responses = await Promise.all([
      current.fetch(new Request('http://defender.example/healthz/extra')),
      current.fetch(new Request('http://defender.example/healthz?verbose=true')),
      current.fetch(new Request('http://127.0.0.1:3020/healthz', { method: 'POST' })),
    ]);

    expect(responses.map(({ status }) => status)).toEqual([404, 404, 405]);
    expect(current.create).not.toHaveBeenCalled();
  });

  it('rejects cross-origin browser requests before authentication', async () => {
    const response = await handler().fetch(
      new Request('http://defender.example/mcp', {
        headers: { origin: 'https://attacker.example' },
      }),
    );

    expect(response.status).toBe(403);
  });

  it('rejects an attacker-controlled Host even when Origin matches it', async () => {
    const response = await handler().fetch(
      new Request('http://attacker.example/mcp', {
        headers: { origin: 'https://attacker.example' },
      }),
    );

    expect(response.status).toBe(403);
  });

  it('reports JWKS infrastructure failures as server errors without blaming the token', async () => {
    const report = vi.fn();
    const failingGetKey: JWTVerifyGetKey = () =>
      Promise.reject(new TypeError('simulated JWKS network failure'));
    const current = createHttpFetchHandler(
      config,
      new EntraTokenVerifier(config, failingGetKey, report),
      { create: () => authenticatedProvider() },
    );
    const response = await current.fetch(toolRequest(await token(), 1));

    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toMatchObject({ error: 'server_error' });
    expect(report).toHaveBeenCalledWith('Entra JWKS verification is unavailable (TypeError)');
  });

  it('accumulates tenant-wide rate-limit attempts across separate HTTP requests', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockImplementation(() =>
        Promise.resolve(new Response(JSON.stringify({ value: [] }), { status: 200 })),
      );
    vi.stubGlobal('fetch', fetchMock);
    const bearer = await token();
    const append = vi.fn(() => Promise.resolve());
    const state = sharedState(append);
    const create = vi.fn(() => authenticatedProvider());
    const current = createHttpFetchHandler(
      config,
      new EntraTokenVerifier(config, getKey),
      { create },
      state,
    );

    const first = await current.fetch(toolRequest(bearer, 1));
    const second = await current.fetch(toolRequest(bearer, 2));

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    await Promise.all([first.text(), second.text()]);
    expect(create).toHaveBeenCalledTimes(2);
    expect(state.rateLimiter.state().attempts['graph-other']).toBe(2);
    expect(append).toHaveBeenCalledTimes(2);
  });

  it('redeems a continuation token on a later HTTP request', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            value: [{ id: 'incident-1' }],
            '@odata.nextLink':
              'https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=next-page',
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ value: [{ id: 'incident-2' }] }), { status: 200 }),
      );
    vi.stubGlobal('fetch', fetchMock);
    const bearer = await token();
    const current = createHttpFetchHandler(
      config,
      new EntraTokenVerifier(config, getKey),
      { create: () => authenticatedProvider() },
      sharedState(),
    );

    const first = await current.fetch(toolRequest(bearer, 1));
    const continuation = /\\"continuationToken\\":\\"([^\\"]+)\\"/.exec(await first.text())?.[1];
    expect(continuation).toEqual(expect.any(String));
    if (continuation === undefined) throw new Error('First page did not return a continuation');
    const second = await current.fetch(toolRequest(bearer, 2, { continuationToken: continuation }));

    expect(second.status).toBe(200);
    expect(await second.text()).not.toContain('expired or was already used');
    expect(fetchMock.mock.calls[1]?.[0]).toEqual(
      new URL('https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=next-page'),
    );
  });
});
