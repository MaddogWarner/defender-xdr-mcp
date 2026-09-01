import { describe, expect, it } from 'vitest';

import { HUNTING_TABLES } from '../../src/schema/huntingTables.js';

describe('HUNTING_TABLES', () => {
  it('covers the core Defender XDR hunting families', () => {
    const names = new Set(HUNTING_TABLES.map(({ name }) => name));

    expect(HUNTING_TABLES.length).toBeGreaterThanOrEqual(30);
    for (const name of [
      'DeviceProcessEvents',
      'EmailEvents',
      'IdentityLogonEvents',
      'CloudAppEvents',
      'AlertInfo',
      'ExposureGraphNodes',
    ]) {
      expect(names.has(name)).toBe(true);
    }
    expect(HUNTING_TABLES.every(({ keyColumns }) => keyColumns.length > 0)).toBe(true);
  });
});
