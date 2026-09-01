import {
  ClientAuthError,
  ClientAuthErrorCodes,
  InteractionRequiredAuthError,
  type AccountInfo,
  type AuthenticationResult,
  type DeviceCodeRequest,
  type SilentFlowRequest,
} from '@azure/msal-node';
import { describe, expect, it, vi } from 'vitest';

import {
  DeviceCodeAuth,
  GRAPH_SCOPES,
  MDE_TOKEN_SCOPES,
  ResourceInteractionRequiredError,
} from '../../src/auth/msal.js';

const account: AccountInfo = {
  homeAccountId: 'home-account',
  environment: 'login.microsoftonline.com',
  tenantId: '11111111-1111-4111-8111-111111111111',
  username: 'analyst@example.com',
  localAccountId: 'local-account',
  name: 'Security Analyst',
};

function result(scopes: readonly string[], accessToken = 'test-token'): AuthenticationResult {
  return {
    authority: 'https://login.microsoftonline.com/tenant',
    uniqueId: account.localAccountId,
    tenantId: account.tenantId,
    scopes: [...scopes],
    account,
    idToken: 'test-id-token',
    idTokenClaims: {},
    accessToken,
    fromCache: false,
    expiresOn: new Date(Date.now() + 3_600_000),
    tokenType: 'Bearer',
    correlationId: 'correlation-id',
  };
}

describe('DeviceCodeAuth', () => {
  it('selects distinct scopes for Graph and MDE', async () => {
    const acquireTokenSilent = vi
      .fn<(request: SilentFlowRequest) => Promise<AuthenticationResult>>()
      .mockImplementation((request) => Promise.resolve(result(request.scopes)));
    const application = {
      getAllAccounts: vi.fn(() => Promise.resolve([account])),
      acquireTokenSilent,
      acquireTokenByDeviceCode: vi
        .fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>()
        .mockResolvedValue(null),
    };
    const auth = new DeviceCodeAuth(application);

    await auth.getToken('graph');
    await auth.getToken('mde');

    expect(acquireTokenSilent.mock.calls[0]?.[0].scopes).toEqual(GRAPH_SCOPES);
    expect(acquireTokenSilent.mock.calls[1]?.[0].scopes).toEqual(MDE_TOKEN_SCOPES);
  });

  it('uses device code when no cached account exists', async () => {
    const acquireTokenByDeviceCode = vi
      .fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>()
      .mockResolvedValue(result(GRAPH_SCOPES));
    const application = {
      getAllAccounts: vi.fn(() => Promise.resolve([])),
      acquireTokenSilent: vi
        .fn<(_request: SilentFlowRequest) => Promise<AuthenticationResult>>()
        .mockRejectedValue(new Error('must not be called')),
      acquireTokenByDeviceCode,
    };

    await new DeviceCodeAuth(application).getToken('graph');

    expect(acquireTokenByDeviceCode).toHaveBeenCalledOnce();
  });

  it('falls back to device code only when interaction is required', async () => {
    const acquireTokenByDeviceCode = vi
      .fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>()
      .mockResolvedValue(result(MDE_TOKEN_SCOPES));
    const application = {
      getAllAccounts: vi.fn(() => Promise.resolve([account])),
      acquireTokenSilent: vi
        .fn<(_request: SilentFlowRequest) => Promise<AuthenticationResult>>()
        .mockRejectedValue(
          new InteractionRequiredAuthError('interaction_required', 'Sign-in required'),
        ),
      acquireTokenByDeviceCode,
    };

    await new DeviceCodeAuth(application).getToken('mde');

    expect(acquireTokenByDeviceCode).toHaveBeenCalledOnce();
  });

  it('does not expose token material in connection status', async () => {
    const application = {
      getAllAccounts: vi.fn(() => Promise.resolve([account])),
      acquireTokenSilent: vi.fn((request: SilentFlowRequest) =>
        Promise.resolve(result(request.scopes, 'sensitive-token')),
      ),
      acquireTokenByDeviceCode: vi
        .fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>()
        .mockResolvedValue(null),
    };
    const auth = new DeviceCodeAuth(application);

    await auth.getToken('graph');

    expect(JSON.stringify(auth.getConnectionStatus())).not.toContain('sensitive-token');
    expect(auth.getConnectionStatus().upn).toBe(account.username);
  });

  it('reuses an unexpired in-memory access token', async () => {
    const acquireTokenSilent = vi
      .fn<(request: SilentFlowRequest) => Promise<AuthenticationResult>>()
      .mockImplementation((request) => Promise.resolve(result(request.scopes)));
    const getAllAccounts = vi.fn(() => Promise.resolve([account]));
    const auth = new DeviceCodeAuth({
      getAllAccounts,
      acquireTokenSilent,
      acquireTokenByDeviceCode: vi
        .fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>()
        .mockResolvedValue(null),
    });

    await auth.getToken('graph');
    await auth.getToken('graph');

    expect(getAllAccounts).toHaveBeenCalledOnce();
    expect(acquireTokenSilent).toHaveBeenCalledOnce();
  });

  it('does not select an arbitrary account when several are cached', async () => {
    const secondAccount = { ...account, homeAccountId: 'second', username: 'other@example.com' };
    const acquireTokenByDeviceCode = vi
      .fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>()
      .mockResolvedValue(result(GRAPH_SCOPES));
    const acquireTokenSilent =
      vi.fn<(_request: SilentFlowRequest) => Promise<AuthenticationResult>>();
    const auth = new DeviceCodeAuth({
      getAllAccounts: vi.fn(() => Promise.resolve([account, secondAccount])),
      acquireTokenSilent,
      acquireTokenByDeviceCode,
    });

    await auth.getToken('graph');

    expect(acquireTokenSilent).not.toHaveBeenCalled();
    expect(acquireTokenByDeviceCode).toHaveBeenCalledOnce();
  });

  it('uses device code when the silent cache has no usable token', async () => {
    const acquireTokenByDeviceCode = vi
      .fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>()
      .mockResolvedValue(result(GRAPH_SCOPES));
    const auth = new DeviceCodeAuth({
      getAllAccounts: vi.fn(() => Promise.resolve([account])),
      acquireTokenSilent: vi
        .fn<(_request: SilentFlowRequest) => Promise<AuthenticationResult>>()
        .mockRejectedValue(
          new ClientAuthError(ClientAuthErrorCodes.noAccountFound, 'correlation-id'),
        ),
      acquireTokenByDeviceCode,
    });

    await auth.getToken('graph');

    expect(acquireTokenByDeviceCode).toHaveBeenCalledOnce();
  });

  it('silently acquires after restart when a cached account exists', async () => {
    const acquireTokenSilent = vi
      .fn<(request: SilentFlowRequest) => Promise<AuthenticationResult>>()
      .mockImplementation((request) => Promise.resolve(result(request.scopes)));
    const acquireTokenByDeviceCode =
      vi.fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>();
    const auth = new DeviceCodeAuth({
      getAllAccounts: vi.fn(() => Promise.resolve([account])),
      acquireTokenSilent,
      acquireTokenByDeviceCode,
    });

    await expect(auth.hasUsableToken('graph')).resolves.toBe(true);

    expect(acquireTokenSilent).toHaveBeenCalledOnce();
    expect(acquireTokenByDeviceCode).not.toHaveBeenCalled();
  });

  it('reports interaction-required without starting device code from a domain call', async () => {
    const acquireTokenByDeviceCode =
      vi.fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>();
    const auth = new DeviceCodeAuth({
      getAllAccounts: vi.fn(() => Promise.resolve([])),
      acquireTokenSilent: vi.fn<(_request: SilentFlowRequest) => Promise<AuthenticationResult>>(),
      acquireTokenByDeviceCode,
    });

    await expect(auth.hasUsableToken('mde')).resolves.toBe(false);
    await expect(auth.getTokenSilently('mde')).rejects.toBeInstanceOf(
      ResourceInteractionRequiredError,
    );
    expect(acquireTokenByDeviceCode).not.toHaveBeenCalled();
  });

  it('invalidates only the requested resource token', async () => {
    const acquireTokenSilent = vi
      .fn<(request: SilentFlowRequest) => Promise<AuthenticationResult>>()
      .mockImplementation((request) => Promise.resolve(result(request.scopes)));
    const auth = new DeviceCodeAuth({
      getAllAccounts: vi.fn(() => Promise.resolve([account])),
      acquireTokenSilent,
      acquireTokenByDeviceCode:
        vi.fn<(_request: DeviceCodeRequest) => Promise<AuthenticationResult | null>>(),
    });

    await auth.getTokenSilently('graph');
    await auth.getTokenSilently('mde');
    auth.invalidate('mde');
    await auth.getTokenSilently('graph');
    await auth.getTokenSilently('mde');

    expect(acquireTokenSilent).toHaveBeenCalledTimes(3);
  });
});
