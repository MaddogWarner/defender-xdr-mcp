import { describe, expect, it } from 'vitest';

import { ContinuationTokenStore } from '../../src/clients/continuationTokens.js';

describe('ContinuationTokenStore', () => {
  it('issues an opaque token and redeems it to a same-origin path once', () => {
    const store = new ContinuationTokenStore(['https://graph.microsoft.com'], {
      createId: () => 'opaque-id',
    });

    const token = store.issue('https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=x');

    expect(token).toBe('opaque-id');
    expect(store.redeem(token)).toBe('/v1.0/security/incidents?$skiptoken=x');
    expect(() => store.redeem(token)).toThrow(/expired or was already used/);
  });

  it('rejects continuation URLs outside the configured HTTPS origin', () => {
    const store = new ContinuationTokenStore(['https://graph.microsoft.com']);

    expect(() => store.issue('https://attacker.example/steal')).toThrow(/configured hosts/);
    expect(() => store.issue('http://graph.microsoft.com/unsafe')).toThrow(/configured hosts/);
  });

  it('expires entries after no more than ten minutes', () => {
    let now = 0;
    const store = new ContinuationTokenStore(['https://graph.microsoft.com'], {
      ttlMs: 60 * 60 * 1000,
      now: () => now,
      createId: () => 'opaque-id',
    });
    const token = store.issue('https://graph.microsoft.com/v1.0/security/incidents');

    now = 10 * 60 * 1000;

    expect(() => store.redeem(token)).toThrow(/expired or was already used/);
  });

  it('evicts the least-recently-issued entry when bounded capacity is reached', () => {
    const ids = ['first', 'second'];
    const store = new ContinuationTokenStore(['https://graph.microsoft.com'], {
      maximumEntries: 1,
      createId: () => ids.shift() ?? 'unexpected',
    });
    const first = store.issue('https://graph.microsoft.com/first');
    const second = store.issue('https://graph.microsoft.com/second');

    expect(() => store.redeem(first)).toThrow(/expired or was already used/);
    expect(store.redeem(second)).toBe('/second');
  });
});
