import { chmod, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { ICachePlugin } from '@azure/msal-node';
import {
  DataProtectionScope,
  PersistenceCachePlugin,
  PersistenceCreator,
} from '@azure/msal-node-extensions';

const CACHE_DIRECTORY = '.defender-xdr-mcp';
const CACHE_FILENAME = 'msal-cache.bin';

export async function createEncryptedCachePlugin(clientId: string): Promise<ICachePlugin> {
  const directory = join(homedir(), CACHE_DIRECTORY);
  const cachePath = join(directory, CACHE_FILENAME);

  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);

    const persistence = await PersistenceCreator.createPersistence({
      cachePath,
      dataProtectionScope: DataProtectionScope.CurrentUser,
      serviceName: 'defender-xdr-mcp',
      accountName: clientId,
      usePlaintextFileOnLinux: false,
    });

    await chmod(cachePath, 0o600);
    return new PersistenceCachePlugin(persistence);
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : 'unknown keystore error';
    throw new Error(
      `Encrypted MSAL token cache is unavailable (${detail}). Configure macOS Keychain, Windows DPAPI, or a running Linux Secret Service with libsecret; plaintext fallback is disabled.`,
      { cause: error },
    );
  }
}
