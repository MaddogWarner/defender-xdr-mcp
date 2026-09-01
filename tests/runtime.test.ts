import type { serveStdio, StdioServerHandle } from '@modelcontextprotocol/server/stdio';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { DeviceCodeAuth } from '../src/auth/msal.js';
import type { AppConfig } from '../src/config.js';
import { startStdio } from '../src/runtime.js';

const config = {} as AppConfig;

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

describe('startStdio', () => {
  it('starts production stdio without acquiring a token eagerly', async () => {
    const getToken = vi.fn<DeviceCodeAuth['getToken']>();
    const auth = { getToken } as unknown as DeviceCodeAuth;
    const close = vi.fn(() => Promise.resolve());
    const handle: StdioServerHandle = { close };
    const serve = vi.fn<typeof serveStdio>().mockReturnValue(handle);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);

    const runtime = await startStdio(config, auth, false, serve);

    expect(getToken).not.toHaveBeenCalled();
    expect(serve).toHaveBeenCalledOnce();
    await runtime.close();
    expect(close).toHaveBeenCalledOnce();
  });

  it('reports asynchronous transport errors through stderr and the exit code', async () => {
    const auth = { getToken: vi.fn<DeviceCodeAuth['getToken']>() } as unknown as DeviceCodeAuth;
    const handle: StdioServerHandle = { close: vi.fn(() => Promise.resolve()) };
    const serve = vi.fn<typeof serveStdio>().mockReturnValue(handle);
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    await startStdio(config, auth, false, serve);
    const options = serve.mock.calls[0]?.[1];
    options?.onerror?.(new Error('broken pipe'));

    expect(stderr).toHaveBeenCalledWith('MCP stdio transport failed: broken pipe');
    expect(process.exitCode).toBe(1);
  });
});
