import { describe, expect, it } from 'vitest';

import { validateKql } from '../../src/guardrails/kqlValidator.js';

const config = { defaultTimespan: 'P7D', maxTimespan: 'P30D', maxRows: 1000 };

describe('validateKql', () => {
  it.each([undefined, null, 42, '', '   '])('rejects an empty or non-string query: %j', (query) => {
    expect(validateKql(query, undefined, config)).toEqual({
      ok: false,
      reason: 'The KQL query must be a non-empty string.',
    });
  });

  it.each([
    'externaldata(value:string)[h@"https://example.invalid"]',
    'EXTERNALDATA (value:string) [h@"https://example.invalid"]',
    'externaldata\n(value:string)[h@"https://example.invalid"]',
  ])('rejects the externaldata operator robustly', (query) => {
    const result = validateKql(query, undefined, config);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toContain('externaldata');
  });

  it.each([
    `print value='externaldata(value:string)'`,
    `print value="externaldata(value:string)"`,
    `DeviceInfo // externaldata(value:string)\n| take 5`,
    `print value='it''s externaldata here'`,
    String.raw`print value=@"c:\externaldata(value:string)"`,
    String.raw`print value=@'c:\externaldata(value:string)'`,
    `print value=h"externaldata(value:string)"`,
    String.raw`print value=H@'externaldata(value:string)'`,
    'print value=```externaldata(value:string)```',
  ])('ignores externaldata inside literals and comments', (query) => {
    expect(validateKql(query, undefined, config).ok).toBe(true);
  });

  it.each([
    String.raw`let a = @"c:\";
externaldata(x:string)[@"https://evil.example/x"]`,
    String.raw`let a = @'c:\';
externaldata(x:string)[@'https://evil.example/x']`,
    `let a = h"secret";\nexternaldata(x:string)["https://evil.example/x"]`,
    String.raw`let a = H@'secret';
externaldata(x:string)[@'https://evil.example/x']`,
    'let a = ```multi\nline```;\nexternaldata(x:string)["https://evil.example/x"]',
  ])('detects externaldata following a complete Kusto literal', (query) => {
    const result = validateKql(query, undefined, config);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toContain('externaldata');
  });

  it.each([
    `adx('cluster/database').Table`,
    `ADX('cluster/database').Table`,
    `adx \n ('cluster/database').Table`,
    String.raw`let value = @"c:\";
adx('cluster/database').Table`,
    String.raw`let value = @'c:\';
adx('cluster/database').Table`,
    `let value = @"say ""hi"" ok";\nadx('cluster/database').Table`,
    "let value = ```multi\nline```;\nadx('cluster/database').Table",
    `let value = h"secret";\nadx('cluster/database').Table`,
    String.raw`let value = H@'secret';
adx('cluster/database').Table`,
  ])('rejects adx() calls outside Kusto literals and comments', (query) => {
    expect(validateKql(query, undefined, config)).toEqual({
      ok: false,
      reason:
        'The adx() function is not allowed because it can retrieve data from an external Azure Data Explorer cluster. Use a Defender XDR table instead.',
    });
  });

  it.each([
    'DeviceInfo | project adx = DeviceName',
    `DeviceInfo // adx('cluster/database').Table\n| take 5`,
    `print value="adx('cluster/database').Table"`,
  ])('allows adx identifiers and references inside literals or comments', (query) => {
    expect(validateKql(query, undefined, config).ok).toBe(true);
  });

  it.each([
    'print value=@"c:\\',
    "print value=H@'secret",
    'print value="escaped quote\\"',
    'print value=```multi\nline',
  ])('fails closed on an unterminated Kusto literal', (query) => {
    expect(validateKql(query, undefined, config)).toEqual({
      ok: false,
      reason: 'The KQL query contains an unterminated string literal. Close the literal and retry.',
    });
  });

  it('does not treat C-style block markers as KQL comments', () => {
    const result = validateKql('DeviceInfo /* externaldata(value:string) */', undefined, config);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toContain('externaldata');
  });

  it.each(['take', 'limit', 'top'])('does not append a cap after a smaller %s', (operator) => {
    const query = `DeviceInfo | ${operator} 10`;
    expect(validateKql(query, undefined, config)).toMatchObject({ ok: true, query });
  });

  it('appends the configured cap when no smaller row operator exists', () => {
    expect(validateKql('DeviceInfo | project DeviceName', undefined, config)).toMatchObject({
      ok: true,
      query: 'DeviceInfo | project DeviceName\n| take 1000',
    });
    expect(validateKql('DeviceInfo | take 5000', undefined, config)).toMatchObject({
      ok: true,
      query: 'DeviceInfo | take 5000\n| take 1000',
    });
  });

  it.each([
    'let sample = DeviceInfo | take 5;\nsample',
    'DeviceInfo | where DeviceId in (DeviceInfo | take 5 | project DeviceId)',
    'union (DeviceInfo | take 5), DeviceProcessEvents',
  ])('does not let a nested row operator defeat the outer result cap', (query) => {
    expect(validateKql(query, undefined, config)).toMatchObject({
      ok: true,
      query: `${query}\n| take 1000`,
    });
  });

  it('applies the default, clamps oversized spans, and rejects invalid spans', () => {
    expect(validateKql('DeviceInfo | take 5', undefined, config)).toMatchObject({
      ok: true,
      timespan: 'P7D',
    });
    const clamped = validateKql('DeviceInfo | take 5', 'P31D', config);
    expect(clamped).toMatchObject({ ok: true, timespan: 'P30D' });
    expect(clamped.ok && clamped.notices.join(' ')).toContain('clamped');
    expect(validateKql('DeviceInfo', 'last week', config)).toMatchObject({ ok: false });
    expect(validateKql('DeviceInfo', 7, config)).toMatchObject({ ok: false });
  });

  it('warns without blocking union-star queries', () => {
    const result = validateKql('union * | project Timestamp', undefined, config);
    expect(result).toMatchObject({ ok: true });
    expect(result.ok && result.notices.join(' ')).toContain('union *');
  });

  it('does not warn when a union-star query includes a filter', () => {
    const result = validateKql('union * | where Timestamp > ago(1h)', undefined, config);
    expect(result.ok && result.notices.join(' ')).not.toContain('union *');
  });
});
