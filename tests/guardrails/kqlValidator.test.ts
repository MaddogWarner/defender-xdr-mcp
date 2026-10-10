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
    'external_data(x:string)',
    'External_Data(x:string)',
    'external_datatable(x:string)',
    'inline_external_table(x:string)',
    "external_table('x')",
    "cluster('c').database('d').T",
    "database('d').T",
    "cluster ('c').T",
    "database\n('d').T",
    'DeviceInfo | evaluate http_request()',
    'DeviceInfo | evaluate http_request_post()',
    'DeviceInfo | evaluate sql_request()',
    'DeviceInfo | evaluate cosmosdb_sql_request()',
    'DeviceInfo | evaluate mysql_request()',
    'DeviceInfo | evaluate postgresql_request()',
    'DeviceInfo | evaluate future_request()',
    'DeviceInfo | evaluate   http_request()',
    'DeviceInfo | EVALUATE HTTP_REQUEST_POST()',
    'DeviceInfo | evaluate // plugin\nhttp_request()',
    "['external_data'](x:string)",
    '["External_Table"]("x")',
    "['cluster']('c').T",
    "['clu' 'ster']('c').T",
    "['cluster' // name\n]('c').T",
    "['cluster'] // call\n('c').T",
    "DeviceInfo | evaluate hint.distribution=single http_request('x')",
    "DeviceInfo | evaluate hint.remote=local ['http_request_post']('x')",
    "[ 'database' ]\n('d').T",
    "DeviceInfo | evaluate ['http_request']()",
    String.raw`['clu\u0073ter']('c').T`,
    String.raw`['clu\x73ter']('c').T`,
    String.raw`['clu\163ter']('c').T`,
    String.raw`['clu\ster']('c').T`,
    "[@'cluster']('c').T",
    '[h@"database"]("d").T',
    '[```cluster```]("c").T',
    'DeviceInfo | project adx = DeviceName',
  ])('rejects a blocked whole identifier: %s', (query) => {
    const result = validateKql(query, undefined, config);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(
      /^External data access \([a-z]+\) is not allowed\. Use a Defender XDR table instead\.$/,
    );
  });

  const deniedNames = [
    'externaldata',
    'external_data',
    'external_table',
    'external_datatable',
    'inline_external_table',
    'adx',
    'cluster',
    'database',
    'evaluate http_request',
    'evaluate http_request_post',
    'evaluate sql_request',
    'evaluate cosmosdb_sql_request',
    'evaluate mysql_request',
    'evaluate postgresql_request',
  ];
  it.each(deniedNames)('ignores %s in all supported literal and comment forms', (name) => {
    for (const query of [
      `print value='${name}'`,
      `print value="${name}"`,
      `print value=@'${name}'`,
      `print value=@"${name}"`,
      `print value=h'${name}'`,
      `print value=h"${name}"`,
      `print value=H@'${name}'`,
      `print value=h@"${name}"`,
      'print value=```' + name + '```',
      `DeviceInfo // ${name}\n| take 5`,
      `print value=dynamic(["${name}"])`,
      `print value="['${name}']()"`,
    ])
      expect(validateKql(query, undefined, config).ok, query).toBe(true);
  });

  it.each([
    'DeviceInfo | evaluate bag_unpack(x)',
    'DeviceInfo | evaluate autocluster()',
    'DeviceInfo | evaluate basket()',
    'DeviceInfo | evaluate ["bag_unpack"](x)',
    'DeviceInfo | project ExternalDataSize, my_cluster, database_count, adx_result',
    'DeviceInfo | project ["ExternalDataSize"]',
    'DeviceInfo | evaluate http_request_count()',
    'DeviceInfo | extend http_request = 1',
    'print value=1',
    'DeviceInfo | extend value=[@"safe""name"]()',
    String.raw`DeviceInfo | extend value=['safe\nname']()`,
  ])('allows legitimate identifiers and plugins: %s', (query) => {
    expect(validateKql(query, undefined, config).ok).toBe(true);
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
      reason: 'External data access (adx) is not allowed. Use a Defender XDR table instead.',
    });
  });

  it.each([
    `DeviceInfo // adx('cluster/database').Table\n| take 5`,
    `print value="adx('cluster/database').Table"`,
  ])('allows adx references inside literals or comments', (query) => {
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

  it('inserts the configured cap before a trailing render operator', () => {
    expect(validateKql('T | render timechart', undefined, config)).toMatchObject({
      ok: true,
      query: 'T\n| take 1000 | render timechart',
    });
  });

  it('does not add a second cap before render when the outer result is already bounded', () => {
    const query = 'T | take 10 | render barchart';
    expect(validateKql(query, undefined, config)).toMatchObject({ ok: true, query });
  });

  it.each([
    'T | extend message="| render timechart"',
    'T // | render timechart',
    'T | where Key in (U | render table)',
  ])('ignores render outside the final outer pipe stage: %s', (query) => {
    expect(validateKql(query, undefined, config)).toMatchObject({
      ok: true,
      query: `${query}\n| take 1000`,
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
