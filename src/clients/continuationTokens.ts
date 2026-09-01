import { randomUUID } from 'node:crypto';

interface StoredContinuation {
  url: string;
  expiresAt: number;
}

interface ContinuationTokenStoreOptions {
  maximumEntries?: number;
  ttlMs?: number;
  now?: () => number;
  createId?: () => string;
}

const DEFAULT_MAXIMUM_ENTRIES = 4096;
const DEFAULT_TTL_MS = 10 * 60 * 1000;

export class ContinuationTokenError extends Error {
  constructor() {
    super('That continuation token expired or was already used. Re-run the original query.');
    this.name = 'ContinuationTokenError';
  }
}

export class ContinuationTokenStore {
  readonly #allowedOrigins: ReadonlySet<string>;
  readonly #maximumEntries: number;
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #createId: () => string;
  readonly #entries = new Map<string, StoredContinuation>();

  constructor(allowedOrigins: readonly string[], options: ContinuationTokenStoreOptions = {}) {
    this.#allowedOrigins = new Set(allowedOrigins.map((origin) => new URL(origin).origin));
    this.#maximumEntries = Math.max(1, options.maximumEntries ?? DEFAULT_MAXIMUM_ENTRIES);
    this.#ttlMs = Math.max(1, Math.min(options.ttlMs ?? DEFAULT_TTL_MS, DEFAULT_TTL_MS));
    this.#now = options.now ?? Date.now;
    this.#createId = options.createId ?? randomUUID;
  }

  issue(nextLink: string): string {
    const url = this.#validateUrl(nextLink);
    this.#removeExpired();
    while (this.#entries.size >= this.#maximumEntries) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
    const id = this.#createId();
    this.#entries.set(id, { url: url.toString(), expiresAt: this.#now() + this.#ttlMs });
    return id;
  }

  redeem(id: string): string {
    const stored = this.#entries.get(id);
    this.#entries.delete(id);
    if (stored === undefined || stored.expiresAt <= this.#now()) {
      throw new ContinuationTokenError();
    }
    const url = this.#validateUrl(stored.url);
    return `${url.pathname}${url.search}`;
  }

  #removeExpired(): void {
    const now = this.#now();
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt <= now) this.#entries.delete(id);
    }
  }

  #validateUrl(value: string): URL {
    const url = new URL(value);
    if (url.protocol !== 'https:' || !this.#allowedOrigins.has(url.origin)) {
      throw new Error('Microsoft continuation URL resolved outside the configured hosts');
    }
    return url;
  }
}
