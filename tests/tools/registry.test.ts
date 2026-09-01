import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { SERVER_VERSION } from '../../src/tools/registry.js';

describe('server release metadata', () => {
  it('keeps the MCP and health version aligned with package.json', async () => {
    const packageJson: unknown = JSON.parse(
      await readFile(new URL('../../package.json', import.meta.url), 'utf8'),
    );

    expect(packageJson).toMatchObject({ version: SERVER_VERSION });
  });
});
