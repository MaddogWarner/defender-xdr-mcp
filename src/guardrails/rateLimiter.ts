import type { ApiFamily, RateLimiterState, RequestRateLimiter } from '../clients/http.js';

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;

export interface WindowLimit {
  requestsPerMinute: number;
  requestsPerHour: number;
}

export type RateLimitConfiguration = Readonly<Record<ApiFamily, WindowLimit>>;

interface RateLimiterOptions {
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  maxWaitMs?: number;
}

interface FamilyState {
  minuteTokens: number;
  lastRefill: number;
  hourlyAttempts: number[];
}

export class LocalRateLimitError extends Error {
  readonly family: ApiFamily;
  readonly window: 'minute' | 'hour';
  readonly retryAfterSeconds: number;

  constructor(family: ApiFamily, window: 'minute' | 'hour', retryAfterMs: number) {
    const retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
    super(
      `Rate limited locally for ${family}: the per-${window} budget is exhausted; retry in ${retryAfterSeconds}s.`,
    );
    this.name = 'LocalRateLimitError';
    this.family = family;
    this.window = window;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class DualWindowRateLimiter implements RequestRateLimiter {
  readonly #limits: RateLimitConfiguration;
  readonly #states: Record<ApiFamily, FamilyState>;
  readonly #attempts: Record<ApiFamily, number> = {
    hunting: 0,
    'graph-other': 0,
    mde: 0,
  };
  readonly #now: () => number;
  readonly #sleep: (milliseconds: number) => Promise<void>;
  readonly #maxWaitMs: number;
  #lock: Promise<void> = Promise.resolve();

  constructor(limits: RateLimitConfiguration, options: RateLimiterOptions = {}) {
    const started = options.now?.() ?? Date.now();
    this.#limits = limits;
    this.#now = options.now ?? Date.now;
    this.#sleep =
      options.sleep ??
      ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.#maxWaitMs = options.maxWaitMs ?? 5_000;
    this.#states = {
      hunting: createState(limits.hunting.requestsPerMinute, started),
      'graph-other': createState(limits['graph-other'].requestsPerMinute, started),
      mde: createState(limits.mde.requestsPerMinute, started),
    };
  }

  async acquire(family: ApiFamily): Promise<void> {
    let waitedMs = 0;
    for (;;) {
      const decision = await this.#exclusively(() => this.#tryAcquire(family));
      if (decision === 0) return;
      if (waitedMs + decision > this.#maxWaitMs) {
        const window = this.#exhaustedWindow(family);
        throw new LocalRateLimitError(family, window, decision);
      }
      await this.#sleep(decision);
      waitedMs += decision;
    }
  }

  state(): RateLimiterState {
    const now = this.#now();
    const windows = {} as Record<ApiFamily, { minuteRemaining: number; hourRemaining: number }>;
    for (const family of apiFamilies) {
      this.#refresh(family, now);
      const state = this.#states[family];
      const limit = this.#limits[family];
      windows[family] = {
        minuteRemaining: Math.max(0, Math.floor(state.minuteTokens)),
        hourRemaining: Math.max(0, limit.requestsPerHour - state.hourlyAttempts.length),
      };
    }
    return { attempts: { ...this.#attempts }, windows };
  }

  async #exclusively<T>(operation: () => T): Promise<T> {
    const previous = this.#lock;
    let release: (() => void) | undefined;
    this.#lock = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return operation();
    } finally {
      release?.();
    }
  }

  #tryAcquire(family: ApiFamily): number {
    const now = this.#now();
    this.#refresh(family, now);
    const state = this.#states[family];
    const limit = this.#limits[family];
    const minuteWait =
      state.minuteTokens >= 1
        ? 0
        : Math.ceil((1 - state.minuteTokens) * (MINUTE_MS / limit.requestsPerMinute));
    const oldestAttempt = state.hourlyAttempts[0];
    const hourWait =
      state.hourlyAttempts.length < limit.requestsPerHour || oldestAttempt === undefined
        ? 0
        : Math.max(1, oldestAttempt + HOUR_MS - now);
    const wait = Math.max(minuteWait, hourWait);
    if (wait > 0) return wait;

    state.minuteTokens -= 1;
    state.hourlyAttempts.push(now);
    this.#attempts[family] += 1;
    return 0;
  }

  #refresh(family: ApiFamily, now: number): void {
    const state = this.#states[family];
    const limit = this.#limits[family];
    const elapsed = Math.max(0, now - state.lastRefill);
    state.minuteTokens = Math.min(
      limit.requestsPerMinute,
      state.minuteTokens + elapsed * (limit.requestsPerMinute / MINUTE_MS),
    );
    state.lastRefill = now;
    while (state.hourlyAttempts[0] !== undefined && state.hourlyAttempts[0] <= now - HOUR_MS) {
      state.hourlyAttempts.shift();
    }
  }

  #exhaustedWindow(family: ApiFamily): 'minute' | 'hour' {
    const now = this.#now();
    this.#refresh(family, now);
    return this.#states[family].hourlyAttempts.length >= this.#limits[family].requestsPerHour
      ? 'hour'
      : 'minute';
  }
}

const apiFamilies: readonly ApiFamily[] = ['hunting', 'graph-other', 'mde'];

function createState(requestsPerMinute: number, now: number): FamilyState {
  return { minuteTokens: requestsPerMinute, lastRefill: now, hourlyAttempts: [] };
}
