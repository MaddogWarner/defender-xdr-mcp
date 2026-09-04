import { describe, expect, it } from 'vitest';

import type { AppConfig } from '../../src/config.js';
import { validateHuntingRequest } from '../../src/tools/hunting.js';

const config = {
  defaultTimespan: 'P7D',
  maxTimespan: 'P30D',
} as AppConfig;

describe('validateHuntingRequest guardrail integration', () => {
  it('applies the configured default timespan', () => {
    expect(
      validateHuntingRequest({ query: 'DeviceInfo | take 5', timespan: undefined }, config, true),
    ).toMatchObject({ ok: true, value: { timespan: 'P7D' } });
  });

  it('clamps a requested timespan and emits a notice', () => {
    const result = validateHuntingRequest(
      { query: 'DeviceInfo | take 5', timespan: 'P60D' },
      config,
      true,
    );

    expect(result).toMatchObject({ ok: true, value: { timespan: 'P30D' } });
    expect(result.ok && result.notices[0]).toMatch(/clamped/);
  });

  it('returns a model-readable validation failure', () => {
    expect(validateHuntingRequest({ query: '  ', timespan: undefined }, config, true)).toEqual({
      ok: false,
      reason: 'The KQL query must be a non-empty string.',
    });
  });

  it('fails fast with an explicit sign-in action before starting a hunting call', () => {
    expect(
      validateHuntingRequest({ query: 'DeviceInfo | take 5', timespan: undefined }, config, false),
    ).toEqual({
      ok: false,
      reason:
        'Not signed in to Microsoft Graph. Run `node dist/index.js --sign-in` in a terminal, or call get_connection_status, then retry.',
    });
  });
});
