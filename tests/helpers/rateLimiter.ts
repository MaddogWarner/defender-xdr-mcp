import type { ApiFamily, RateLimiterState, RequestRateLimiter } from '../../src/clients/http.js';

export class CountingRateLimiter implements RequestRateLimiter {
  readonly #attempts: Record<ApiFamily, number> = {
    hunting: 0,
    'graph-other': 0,
    mde: 0,
  };

  acquire(family: ApiFamily): Promise<void> {
    this.#attempts[family] += 1;
    return Promise.resolve();
  }

  state(): RateLimiterState {
    return { attempts: { ...this.#attempts } };
  }
}
