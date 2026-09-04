import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AccountInfo } from '@azure/msal-node';

import type { AccessTokenContext, DeviceCodeAuth } from '../src/auth/msal.js';
import type { AppConfig } from '../src/config.js';
import type { startHttp } from '../src/http.js';
import { main } from '../src/index.js';
import { authenticateStdio, type RuntimeHandle, type startStdio } from '../src/runtime.js';

const config = { transport: 'stdio' } as AppConfig;
const runtime: RuntimeHandle = { close: () => Promise.resolve() };

function token(username: string): AccessTokenContext {
  return {
    accessToken: 'test-token',
    grantedScopes: [],
    account: { username } as AccountInfo,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('main --sign-in', () => {
  it('acquires Graph then MDE and exits without starting a transport', async () => {
    const getToken = vi
      .fn<DeviceCodeAuth['getToken']>()
      .mockImplementation((resource) => Promise.resolve(token(`${resource}@example.com`)));
    const auth = { getToken } as unknown as DeviceCodeAuth;
    const startStdioMock = vi.fn<typeof startStdio>().mockResolvedValue(runtime);
    const startHttpMock = vi.fn<typeof startHttp>().mockResolvedValue(runtime);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);

    await expect(
      main(['--sign-in'], {
        loadConfig: () => config,
        createDeviceCodeAuth: () => Promise.resolve(auth),
        startHttp: startHttpMock,
        startStdio: startStdioMock,
        authenticateStdio,
      }),
    ).resolves.toBeUndefined();

    expect(getToken.mock.calls.map(([resource]) => resource)).toEqual(['graph', 'mde']);
    expect(startStdioMock).not.toHaveBeenCalled();
    expect(startHttpMock).not.toHaveBeenCalled();
  });

  it('stops before MDE and does not start a transport when Graph authentication fails', async () => {
    const failure = new Error('Graph authentication failed');
    const getToken = vi
      .fn<DeviceCodeAuth['getToken']>()
      .mockRejectedValueOnce(failure)
      .mockResolvedValue(token('mde@example.com'));
    const auth = { getToken } as unknown as DeviceCodeAuth;
    const startStdioMock = vi.fn<typeof startStdio>().mockResolvedValue(runtime);
    const startHttpMock = vi.fn<typeof startHttp>().mockResolvedValue(runtime);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);

    await expect(
      main(['--sign-in'], {
        loadConfig: () => config,
        createDeviceCodeAuth: () => Promise.resolve(auth),
        startHttp: startHttpMock,
        startStdio: startStdioMock,
        authenticateStdio,
      }),
    ).rejects.toBe(failure);

    expect(getToken).toHaveBeenCalledOnce();
    expect(getToken).toHaveBeenCalledWith('graph');
    expect(startStdioMock).not.toHaveBeenCalled();
    expect(startHttpMock).not.toHaveBeenCalled();
  });
});
