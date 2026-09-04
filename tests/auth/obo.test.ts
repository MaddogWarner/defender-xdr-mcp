import type { AuthenticationResult, OnBehalfOfRequest } from '@azure/msal-node';
import { describe, expect, it, vi } from 'vitest';

import { OboTokenCache, OnBehalfOfAuth, OnBehalfOfExchangeError } from '../../src/auth/obo.js';
import { GRAPH_SCOPES, MDE_TOKEN_SCOPES } from '../../src/auth/scopes.js';

const NOW_MS = Date.UTC(2026, 7, 30, 0, 0, 0);
const INBOUND_EXPIRY = NOW_MS / 1000 + 3600;

function result(
  scopes: readonly string[],
  accessToken = 'downstream-token',
  expiresOn = new Date(NOW_MS + 3600_000),
): AuthenticationResult {
  return {
    accessToken,
    scopes: [...scopes],
    expiresOn,
  } as AuthenticationResult;
}

describe('OnBehalfOfAuth', () => {
  it('sweeps expired entries on write and enforces a hard cache bound', () => {
    const cache = new OboTokenCache(2);
    const context = {
      accessToken: 'downstream-token',
      grantedScopes: ['Test.Read'],
      expiresOn: new Date(NOW_MS + 3600_000),
    };
    cache.set('expired', context, NOW_MS + 1000, NOW_MS);
    cache.set('first', context, NOW_MS + 3600_000, NOW_MS + 2000);
    cache.set('second', context, NOW_MS + 3600_000, NOW_MS + 2000);
    cache.set('third', context, NOW_MS + 3600_000, NOW_MS + 2000);

    expect(cache.size).toBe(2);
    expect(cache.get('expired', NOW_MS + 2000)).toBeUndefined();
    expect(cache.get('first', NOW_MS + 2000)).toBeUndefined();
    expect(cache.get('third', NOW_MS + 2000)).toBe(context);
  });

  it('exchanges for Graph and MDE with their distinct delegated scopes', async () => {
    const acquireTokenOnBehalfOf = vi
      .fn<(request: OnBehalfOfRequest) => Promise<AuthenticationResult | null>>()
      .mockImplementation((request) => Promise.resolve(result(request.scopes)));
    const auth = new OnBehalfOfAuth(
      { acquireTokenOnBehalfOf },
      'inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      new OboTokenCache(),
      () => NOW_MS,
    );

    await auth.getToken('graph');
    await auth.getToken('mde');

    expect(acquireTokenOnBehalfOf).toHaveBeenCalledTimes(2);
    expect(acquireTokenOnBehalfOf.mock.calls.map(([request]) => request.scopes)).toEqual(
      expect.arrayContaining([[...GRAPH_SCOPES], [...MDE_TOKEN_SCOPES]]),
    );
    expect(auth.getConnectionStatus().upn).toBe('analyst@example.com');
  });

  it('reuses cached OBO results for the same inbound token without retaining the token as a key', async () => {
    const acquireTokenOnBehalfOf = vi
      .fn<(request: OnBehalfOfRequest) => Promise<AuthenticationResult | null>>()
      .mockResolvedValue(result(GRAPH_SCOPES));
    const application = { acquireTokenOnBehalfOf };
    const cache = new OboTokenCache();
    const first = new OnBehalfOfAuth(
      application,
      'sensitive-inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      cache,
      () => NOW_MS,
    );
    const second = new OnBehalfOfAuth(
      application,
      'sensitive-inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      cache,
      () => NOW_MS,
    );

    await first.getToken('graph');
    await second.getToken('graph');

    expect(acquireTokenOnBehalfOf).toHaveBeenCalledOnce();
    expect(JSON.stringify(cache)).not.toContain('sensitive-inbound-token');
  });

  it('deduplicates concurrent exchanges and reacquires after invalidation', async () => {
    const acquireTokenOnBehalfOf = vi
      .fn<(request: OnBehalfOfRequest) => Promise<AuthenticationResult | null>>()
      .mockResolvedValue(result(GRAPH_SCOPES));
    const auth = new OnBehalfOfAuth(
      { acquireTokenOnBehalfOf },
      'inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      new OboTokenCache(),
      () => NOW_MS,
    );

    await Promise.all([auth.getToken('graph'), auth.getToken('graph')]);
    auth.invalidate('graph');
    await auth.getToken('graph');

    expect(acquireTokenOnBehalfOf).toHaveBeenCalledTimes(2);
  });

  it('does not cache a downstream token inside the five-minute expiry skew', async () => {
    const acquireTokenOnBehalfOf = vi
      .fn<(request: OnBehalfOfRequest) => Promise<AuthenticationResult | null>>()
      .mockResolvedValue(result(GRAPH_SCOPES, 'short-token', new Date(NOW_MS + 299_000)));
    const cache = new OboTokenCache();

    await new OnBehalfOfAuth(
      { acquireTokenOnBehalfOf },
      'inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      cache,
      () => NOW_MS,
    ).getToken('graph');
    await new OnBehalfOfAuth(
      { acquireTokenOnBehalfOf },
      'inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      cache,
      () => NOW_MS,
    ).getToken('graph');

    expect(acquireTokenOnBehalfOf).toHaveBeenCalledTimes(2);
  });

  it.each([
    [
      'invalid_grant',
      "Ask an administrator to confirm the app registration's delegated WindowsDefenderATP permissions have admin consent",
    ],
    [
      'interaction_required',
      "Ask an administrator to grant consent for the app registration's delegated WindowsDefenderATP permissions",
    ],
    [
      'consent_required',
      "Ask an administrator to grant consent for the app registration's delegated WindowsDefenderATP permissions",
    ],
    [
      'unauthorized_client',
      'Ask an administrator to confirm the app registration is authorised for delegated WindowsDefenderATP on-behalf-of access',
    ],
    ['temporarily_unavailable', 'Ask an administrator to review the app registration'],
  ])('maps the %s MSAL failure to safe guidance', async (errorCode, guidance) => {
    const upstream = Object.assign(new Error('raw claims challenge must not escape'), {
      errorCode,
    });
    const auth = new OnBehalfOfAuth(
      { acquireTokenOnBehalfOf: vi.fn().mockRejectedValue(upstream) },
      'sensitive-inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      new OboTokenCache(),
      () => NOW_MS,
    );

    const failure = await auth.getToken('mde').catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(OnBehalfOfExchangeError);
    expect(failure).toMatchObject({ resource: 'mde', errorCode });
    expect((failure as Error).message).toContain(guidance);
    expect((failure as Error).message).not.toContain('raw claims challenge');
    expect((failure as Error).message).not.toContain('sensitive-inbound-token');
  });

  it('maps a missing OBO result without caching it', async () => {
    const acquireTokenOnBehalfOf = vi.fn().mockResolvedValue(null);
    const auth = new OnBehalfOfAuth(
      { acquireTokenOnBehalfOf },
      'inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      new OboTokenCache(),
      () => NOW_MS,
    );

    await expect(auth.getToken('graph')).rejects.toMatchObject({
      name: 'OnBehalfOfExchangeError',
      resource: 'graph',
      errorCode: 'no_token_result',
    });
    await expect(auth.getToken('graph')).rejects.toBeInstanceOf(OnBehalfOfExchangeError);
    expect(acquireTokenOnBehalfOf).toHaveBeenCalledTimes(2);
  });

  it('clears a rejected pending exchange so the next call retries', async () => {
    const acquireTokenOnBehalfOf = vi
      .fn<(request: OnBehalfOfRequest) => Promise<AuthenticationResult | null>>()
      .mockRejectedValueOnce(
        Object.assign(new Error('first failure'), { errorCode: 'invalid_grant' }),
      )
      .mockResolvedValueOnce(result(GRAPH_SCOPES));
    const auth = new OnBehalfOfAuth(
      { acquireTokenOnBehalfOf },
      'inbound-token',
      'analyst@example.com',
      INBOUND_EXPIRY,
      new OboTokenCache(),
      () => NOW_MS,
    );

    await expect(auth.getToken('graph')).rejects.toBeInstanceOf(OnBehalfOfExchangeError);
    await expect(auth.getToken('graph')).resolves.toMatchObject({
      accessToken: 'downstream-token',
    });
    expect(acquireTokenOnBehalfOf).toHaveBeenCalledTimes(2);
  });
});
