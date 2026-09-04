import { describe, expect, it, vi } from 'vitest';

import type { AppConfig } from '../../src/config.js';

vi.mock('@azure/msal-node-extensions', () => {
  throw new Error('stdio encrypted cache dependency loaded');
});

describe('HTTP authentication import boundary', () => {
  it('does not load the stdio-only encrypted cache dependency', async () => {
    await expect(import('../../src/http.js')).resolves.toBeDefined();
  });

  it('loads the encrypted cache dependency when stdio auth is created', async () => {
    const { createDeviceCodeAuth } = await import('../../src/auth/msal.js');
    const config = {
      tenantId: '11111111-1111-4111-8111-111111111111',
      clientId: '22222222-2222-4222-8222-222222222222',
    } as AppConfig;

    await expect(createDeviceCodeAuth(config)).rejects.toThrow(
      'There was an error when mocking a module',
    );
  });
});
