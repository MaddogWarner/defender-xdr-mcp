import { pathToFileURL } from 'node:url';

import { createDeviceCodeAuth } from './auth/msal.js';
import { loadConfig } from './config.js';
import { startHttp } from './http.js';
import { authenticateStdio, startStdio } from './runtime.js';
import type { RuntimeHandle } from './runtime.js';

interface RuntimeDependencies {
  loadConfig: typeof loadConfig;
  createDeviceCodeAuth: typeof createDeviceCodeAuth;
  startHttp: typeof startHttp;
  startStdio: typeof startStdio;
  authenticateStdio: typeof authenticateStdio;
}

const runtimeDependencies: RuntimeDependencies = {
  loadConfig,
  createDeviceCodeAuth,
  startHttp,
  startStdio,
  authenticateStdio,
};

export async function main(
  argumentsValue: readonly string[] = process.argv.slice(2),
  dependencies: RuntimeDependencies = runtimeDependencies,
): Promise<RuntimeHandle | undefined> {
  const config = dependencies.loadConfig();
  if (config.transport === 'http') {
    return dependencies.startHttp(config);
  }

  const auth = await dependencies.createDeviceCodeAuth(config);
  if (argumentsValue.includes('--sign-in')) {
    await dependencies.authenticateStdio(auth);
    return undefined;
  }
  return dependencies.startStdio(config, auth, argumentsValue.includes('--dev-auth-smoke'));
}

function runCli(): void {
  void main()
    .then((runtime) => {
      if (runtime === undefined) return;
      let shutdown: Promise<void> | undefined;
      const close = (exitCode: number): void => {
        shutdown ??= runtime
          .close()
          .then(() => {
            process.exitCode = exitCode;
          })
          .catch((error: unknown) => {
            console.error(error instanceof Error ? error.message : 'Unexpected shutdown failure');
            process.exitCode = 1;
          });
      };
      process.once('SIGINT', () => close(130));
      process.once('SIGTERM', () => close(143));
    })
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : 'Unexpected startup failure');
      process.exitCode = 1;
    });
}

const entryPath = process.argv[1];
if (entryPath !== undefined && import.meta.url === pathToFileURL(entryPath).href) {
  runCli();
}
