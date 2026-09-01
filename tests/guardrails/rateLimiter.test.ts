import { describe, expect, it } from 'vitest';

import {
  DualWindowRateLimiter,
  LocalRateLimitError,
  type RateLimitConfiguration,
} from '../../src/guardrails/rateLimiter.js';

const limits: RateLimitConfiguration = {
  hunting: { requestsPerMinute: 2, requestsPerHour: 10 },
  'graph-other': { requestsPerMinute: 2, requestsPerHour: 10 },
  mde: { requestsPerMinute: 2, requestsPerHour: 10 },
};

describe('DualWindowRateLimiter', () => {
  it('allows a minute burst and returns a structured local limit error', async () => {
    const limiter = new DualWindowRateLimiter(limits, { now: () => 0, maxWaitMs: 0 });
    await limiter.acquire('hunting');
    await limiter.acquire('hunting');
    await expect(limiter.acquire('hunting')).rejects.toMatchObject({
      name: 'LocalRateLimitError',
      family: 'hunting',
      window: 'minute',
      retryAfterSeconds: 30,
    });
  });

  it('refills minute capacity over time', async () => {
    let now = 0;
    const limiter = new DualWindowRateLimiter(limits, { now: () => now, maxWaitMs: 0 });
    await limiter.acquire('mde');
    await limiter.acquire('mde');
    now = 30_000;
    await expect(limiter.acquire('mde')).resolves.toBeUndefined();
    expect(limiter.state().attempts.mde).toBe(3);
  });

  it('serialises concurrent acquires without over-admitting', async () => {
    const limiter = new DualWindowRateLimiter(limits, { now: () => 0, maxWaitMs: 0 });
    const results = await Promise.allSettled([
      limiter.acquire('graph-other'),
      limiter.acquire('graph-other'),
      limiter.acquire('graph-other'),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(2);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
  });

  it('enforces the rolling hourly budget while minute capacity remains', async () => {
    const hourlyLimits: RateLimitConfiguration = {
      ...limits,
      hunting: { requestsPerMinute: 10, requestsPerHour: 2 },
    };
    const limiter = new DualWindowRateLimiter(hourlyLimits, { now: () => 0, maxWaitMs: 0 });
    await limiter.acquire('hunting');
    await limiter.acquire('hunting');
    await expect(limiter.acquire('hunting')).rejects.toMatchObject({ window: 'hour' });
    expect(limiter.state().windows?.hunting).toEqual({
      minuteRemaining: 8,
      hourRemaining: 0,
    });
  });

  it('waits only within the configured bound', async () => {
    let now = 0;
    const sleeps: number[] = [];
    const onePerMinute: RateLimitConfiguration = {
      ...limits,
      mde: { requestsPerMinute: 1, requestsPerHour: 10 },
    };
    const limiter = new DualWindowRateLimiter(onePerMinute, {
      now: () => now,
      maxWaitMs: 60_000,
      sleep: (milliseconds) => {
        sleeps.push(milliseconds);
        now += milliseconds;
        return Promise.resolve();
      },
    });
    await limiter.acquire('mde');
    await limiter.acquire('mde');
    expect(sleeps).toEqual([60_000]);
  });

  it('names the exhausted window in the error message', () => {
    expect(new LocalRateLimitError('mde', 'hour', 1500).message).toContain('per-hour');
  });
});
