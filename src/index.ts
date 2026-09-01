import { createDeviceCodeAuth } from './auth/msal.js';
import { loadConfig } from './config.js';
import { startHttp } from './http.js';
import { startStdio } from './runtime.js';
import type { RuntimeHandle } from './runtime.js';

async function main(): Promise<RuntimeHandle> {
  const config = loadConfig();
  if (config.transport === 'http') {
    return startHttp(config);
  }

  const auth = await createDeviceCodeAuth(config);
  return startStdio(config, auth, process.argv.includes('--dev-auth-smoke'));
}

void main()
  .then((runtime) => {
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
