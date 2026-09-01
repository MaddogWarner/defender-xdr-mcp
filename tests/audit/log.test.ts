import { chmod, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import type { appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { AuditWriteError, JsonlAuditLog, type AuditEntry } from '../../src/audit/log.js';

const temporaryDirectories: string[] = [];
const entry: AuditEntry = {
  ts: '2026-08-29T00:00:00.000Z',
  upn: 'analyst@example.com',
  tool: 'run_hunting_query',
  args: { query: 'DeviceInfo | take 5' },
  rowCount: 5,
  durationMs: 12,
  status: 'success',
};

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })));
});

describe('JsonlAuditLog', () => {
  it('creates a 0600 JSONL file containing metadata and query text, never result rows', async () => {
    const directory = await createTemporaryDirectory();
    const path = join(directory, 'audit.jsonl');
    await new JsonlAuditLog(path, 1, 2).append(entry);

    const content = await readFile(path, 'utf8');
    expect(JSON.parse(content)).toMatchObject(entry);
    expect(content).not.toContain('result rows');
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it('repairs an existing audit file mode before appending', async () => {
    const directory = await createTemporaryDirectory();
    const path = join(directory, 'audit.jsonl');
    const log = new JsonlAuditLog(path, 1, 2);
    await log.append(entry);
    await chmod(path, 0o644);

    await log.append({ ...entry, ts: '2026-08-29T00:00:01.000Z' });

    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it('flushes all queued writes, including after an earlier failure', async () => {
    const directory = await createTemporaryDirectory();
    const path = join(directory, 'audit.jsonl');
    const log = new JsonlAuditLog(path, 1, 2);

    const failed = log.append({ ...entry, args: { value: BigInt(1) } });
    const succeeded = log.append(entry);
    await expect(failed).rejects.toBeInstanceOf(AuditWriteError);
    await log.flush();

    await expect(succeeded).resolves.toBeUndefined();
    await expect(readFile(path, 'utf8')).resolves.toContain(entry.tool);
  });

  it('rotates by size and retains only the configured generations', async () => {
    const directory = await createTemporaryDirectory();
    const path = join(directory, 'audit.jsonl');
    const log = new JsonlAuditLog(path, 0.000_2, 2);
    await log.append(entry);
    await log.append({ ...entry, ts: '2026-08-29T00:00:01.000Z' });
    await log.append({ ...entry, ts: '2026-08-29T00:00:02.000Z' });

    await expect(readFile(`${path}.1`, 'utf8')).resolves.toContain('00:00:01.000Z');
    await expect(readFile(`${path}.2`, 'utf8')).resolves.toContain('00:00:00.000Z');
    await expect(readFile(`${path}.3`, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it.each(['EROFS', 'ENOSPC'])(
    'surfaces %s audit-write failures for fail-closed handling',
    async (code) => {
      const failure = Object.assign(new Error(code), { code });
      const failingAppend = vi.fn(() => Promise.reject(failure)) as unknown as typeof appendFile;
      const log = new JsonlAuditLog('/not-written/audit.jsonl', 1, 2, {
        operations: {
          stat: vi.fn(() =>
            Promise.reject(Object.assign(new Error('missing'), { code: 'ENOENT' })),
          ),
          appendFile: failingAppend,
        },
      });

      await expect(log.append(entry)).rejects.toMatchObject({
        name: 'AuditWriteError',
        cause: failure,
      });
      await expect(log.append(entry)).rejects.toBeInstanceOf(AuditWriteError);
    },
  );
});

async function createTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'defender-xdr-audit-'));
  temporaryDirectories.push(directory);
  return directory;
}
