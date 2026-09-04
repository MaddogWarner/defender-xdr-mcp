import { beforeEach, describe, expect, it, vi } from 'vitest';

const persistenceMocks = vi.hoisted(() => ({
  createPersistence: vi.fn(),
}));

vi.mock('node:fs/promises', () => ({
  chmod: vi.fn().mockResolvedValue(undefined),
  mkdir: vi.fn().mockResolvedValue(undefined),
}));
vi.mock('node:os', () => ({ homedir: () => '/test-home' }));
vi.mock('@azure/msal-node-extensions', () => ({
  DataProtectionScope: { CurrentUser: 'CurrentUser' },
  PersistenceCachePlugin: class PersistenceCachePlugin {},
  PersistenceCreator: { createPersistence: persistenceMocks.createPersistence },
}));

import { createEncryptedCachePlugin } from '../../src/auth/tokenCache.js';

describe('createEncryptedCachePlugin', () => {
  beforeEach(() => {
    persistenceMocks.createPersistence.mockReset();
  });

  it('requires the platform keystore and refuses a plaintext Linux fallback', async () => {
    persistenceMocks.createPersistence.mockRejectedValue(new Error('keystore unavailable'));

    await expect(createEncryptedCachePlugin('client-id')).rejects.toThrow(
      'plaintext fallback is disabled',
    );
    expect(persistenceMocks.createPersistence).toHaveBeenCalledWith(
      expect.objectContaining({ usePlaintextFileOnLinux: false }),
    );
  });
});
