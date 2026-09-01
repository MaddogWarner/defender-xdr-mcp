import { describe, expect, it, vi } from 'vitest';

import type { DeviceCodeAuth } from '../../src/auth/msal.js';
import type { RequestRateLimiter } from '../../src/clients/http.js';
import { getAuthenticatedConnectionStatus } from '../../src/tools/meta.js';

describe('getAuthenticatedConnectionStatus', () => {
  it('acquires Graph authentication before reporting the signed-in user', async () => {
    const getToken = vi.fn<DeviceCodeAuth['getToken']>().mockResolvedValue({
      accessToken: 'not-returned',
      account: { username: 'analyst@example.com' } as never,
      grantedScopes: ['ThreatHunting.Read.All'],
      expiresOn: new Date(Date.now() + 60 * 60 * 1000),
    });
    const auth = {
      getToken,
      getConnectionStatus: () => ({
        upn: 'analyst@example.com',
        scopes: { graph: ['ThreatHunting.Read.All'], mde: [] },
      }),
    };
    const rateLimiter = {
      acquire: () => Promise.resolve(),
      state: () => ({ attempts: { hunting: 0, 'graph-other': 0, mde: 0 } }),
    } satisfies RequestRateLimiter;

    const status = await getAuthenticatedConnectionStatus(
      { tenantId: '11111111-1111-4111-8111-111111111111' },
      auth,
      rateLimiter,
    );

    expect(getToken.mock.calls).toEqual([['graph'], ['mde']]);
    expect(status).toMatchObject({
      tenantId: '11111111-1111-4111-8111-111111111111',
      upn: 'analyst@example.com',
      scopes: { graph: ['ThreatHunting.Read.All'], mde: [] },
    });
    expect(status).not.toHaveProperty('accessToken');
  });
});
