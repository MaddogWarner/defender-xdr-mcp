import { describe, expect, it } from 'vitest';

import { loadConfig } from '../src/config.js';

const requiredEnvironment = {
  DXM_TENANT_ID: '11111111-1111-4111-8111-111111111111',
  DXM_CLIENT_ID: '22222222-2222-4222-8222-222222222222',
};

describe('loadConfig', () => {
  it('loads secure defaults for stdio', () => {
    const config = loadConfig(requiredEnvironment);

    expect(config).toMatchObject({
      transport: 'stdio',
      maxRows: 1000,
      maxResponseBytes: 262144,
      huntingRpm: 40,
      huntingRph: 1200,
      mdeRpm: 45,
      mdeRph: 1350,
      httpHost: '127.0.0.1',
    });
  });

  it('lists all invalid and missing variables', () => {
    expect(() => loadConfig({ DXM_TENANT_ID: 'not-a-guid', DXM_MAX_ROWS: '0' })).toThrow(
      /DXM_TENANT_ID.*DXM_CLIENT_ID.*DXM_MAX_ROWS/,
    );
  });

  it('requires a confidential credential for HTTP mode', () => {
    expect(() =>
      loadConfig({
        ...requiredEnvironment,
        DXM_TRANSPORT: 'http',
        DXM_PUBLIC_URL: 'https://defender.example',
      }),
    ).toThrow(/DXM_CLIENT_SECRET/);
  });

  it('requires an explicit secure public URL for HTTP mode', () => {
    expect(() =>
      loadConfig({
        ...requiredEnvironment,
        DXM_TRANSPORT: 'http',
        DXM_CLIENT_SECRET: 'test-secret',
      }),
    ).toThrow(/DXM_PUBLIC_URL.*required/);
    expect(() =>
      loadConfig({
        ...requiredEnvironment,
        DXM_TRANSPORT: 'http',
        DXM_CLIENT_SECRET: 'test-secret',
        DXM_PUBLIC_URL: 'http://defender.example',
      }),
    ).toThrow(/DXM_PUBLIC_URL.*https/);
    expect(
      loadConfig({
        ...requiredEnvironment,
        DXM_TRANSPORT: 'http',
        DXM_CLIENT_SECRET: 'test-secret',
        DXM_PUBLIC_URL: 'http://127.0.0.1:3020',
      }).publicUrl,
    ).toBe('http://127.0.0.1:3020');
  });

  it('rejects configured limits above Microsoft API ceilings', () => {
    expect(() => loadConfig({ ...requiredEnvironment, DXM_MAX_TIMESPAN: 'P90D' })).toThrow(
      /DXM_MAX_TIMESPAN.*P30D/,
    );
    expect(() => loadConfig({ ...requiredEnvironment, DXM_MAX_ROWS: '999999999' })).toThrow(
      /DXM_MAX_ROWS.*100000/,
    );
    expect(() =>
      loadConfig({ ...requiredEnvironment, DXM_MAX_RESPONSE_BYTES: '999999999' }),
    ).toThrow(/DXM_MAX_RESPONSE_BYTES.*50000000/);
  });

  it('reports an invalid maximum timespan through the configuration error contract', () => {
    expect(() => loadConfig({ ...requiredEnvironment, DXM_MAX_TIMESPAN: 'nope' })).toThrow(
      /Invalid configuration: DXM_MAX_TIMESPAN: must be an ISO 8601 duration/,
    );
  });

  it('rejects a default timespan above the configured maximum', () => {
    expect(() =>
      loadConfig({
        ...requiredEnvironment,
        DXM_DEFAULT_TIMESPAN: 'P14D',
        DXM_MAX_TIMESPAN: 'P7D',
      }),
    ).toThrow(/DXM_DEFAULT_TIMESPAN.*DXM_MAX_TIMESPAN/);
  });
});
