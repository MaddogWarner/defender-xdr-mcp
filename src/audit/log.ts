import { appendFile, chmod, rename, stat, unlink } from 'node:fs/promises';

export interface AuditEntry {
  ts: string;
  upn: string | null;
  tool: string;
  args: Readonly<Record<string, unknown>>;
  rowCount: number;
  durationMs: number;
  status: 'success' | 'error';
  error?: { code?: string };
}

interface AuditFileOperations {
  appendFile: typeof appendFile;
  chmod: typeof chmod;
  rename: typeof rename;
  stat: typeof stat;
  unlink: typeof unlink;
}

interface AuditLogOptions {
  operations?: Partial<AuditFileOperations>;
}

export class AuditWriteError extends Error {
  override readonly cause: unknown;

  constructor(cause: unknown) {
    super('Mandatory audit logging failed; the tool call was not returned.');
    this.name = 'AuditWriteError';
    this.cause = cause;
  }
}

export class JsonlAuditLog {
  readonly #path: string;
  readonly #maximumBytes: number;
  readonly #keep: number;
  readonly #operations: AuditFileOperations;
  #queue: Promise<void> = Promise.resolve();

  constructor(path: string, maximumMegabytes: number, keep: number, options: AuditLogOptions = {}) {
    this.#path = path;
    this.#maximumBytes = maximumMegabytes * 1024 * 1024;
    this.#keep = keep;
    this.#operations = {
      appendFile,
      chmod,
      rename,
      stat,
      unlink,
      ...options.operations,
    };
  }

  append(entry: AuditEntry): Promise<void> {
    const operation = this.#queue.then(() => this.#append(entry));
    this.#queue = operation.catch(() => undefined);
    return operation;
  }

  flush(): Promise<void> {
    return this.#queue;
  }

  async #append(entry: AuditEntry): Promise<void> {
    try {
      const line = `${JSON.stringify(entry)}\n`;
      await this.#secureExistingFile();
      if (await this.#needsRotation(Buffer.byteLength(line, 'utf8'))) {
        await this.#rotate();
      }
      await this.#operations.appendFile(this.#path, line, {
        encoding: 'utf8',
        flag: 'a',
        mode: 0o600,
      });
    } catch (error: unknown) {
      throw new AuditWriteError(error);
    }
  }

  async #secureExistingFile(): Promise<void> {
    try {
      await this.#operations.chmod(this.#path, 0o600);
    } catch (error: unknown) {
      if (!hasCode(error, 'ENOENT')) throw error;
    }
  }

  async #needsRotation(nextLineBytes: number): Promise<boolean> {
    try {
      const current = await this.#operations.stat(this.#path);
      return current.size + nextLineBytes > this.#maximumBytes;
    } catch (error: unknown) {
      if (hasCode(error, 'ENOENT')) return false;
      throw error;
    }
  }

  async #rotate(): Promise<void> {
    await ignoreMissing(() => this.#operations.unlink(`${this.#path}.${this.#keep}`));
    for (let suffix = this.#keep - 1; suffix >= 1; suffix -= 1) {
      await ignoreMissing(() =>
        this.#operations.rename(`${this.#path}.${suffix}`, `${this.#path}.${suffix + 1}`),
      );
    }
    await ignoreMissing(() => this.#operations.rename(this.#path, `${this.#path}.1`));
  }
}

async function ignoreMissing(operation: () => Promise<unknown>): Promise<void> {
  try {
    await operation();
  } catch (error: unknown) {
    if (!hasCode(error, 'ENOENT')) throw error;
  }
}

function hasCode(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && Reflect.get(error, 'code') === code;
}
