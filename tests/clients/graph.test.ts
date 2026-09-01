import { describe, expect, it, vi } from 'vitest';

import { GraphClient } from '../../src/clients/graph.js';
import { ContinuationTokenStore } from '../../src/clients/continuationTokens.js';
import { MicrosoftHttpClient } from '../../src/clients/http.js';
import { CountingRateLimiter } from '../helpers/rateLimiter.js';

describe('GraphClient', () => {
  it('uses the fixed Graph hunting endpoint and request shape', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          schema: [{ name: 'DeviceName', type: 'String' }],
          results: [{ DeviceName: 'host.example' }],
        }),
        { status: 200 },
      ),
    );
    const http = new MicrosoftHttpClient(
      'https://graph.microsoft.com',
      { getToken: () => Promise.resolve('access-token'), invalidate: vi.fn() },
      new CountingRateLimiter(),
      { fetch: fetchMock },
    );

    const result = await new GraphClient(
      http,
      new ContinuationTokenStore(['https://graph.microsoft.com']),
    ).runHuntingQuery('DeviceInfo | take 5', 'P7D');

    expect(result.results).toHaveLength(1);
    expect(fetchMock.mock.calls[0]?.[0]).toEqual(
      new URL('https://graph.microsoft.com/v1.0/security/runHuntingQuery'),
    );
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: 'POST',
      body: JSON.stringify({ Query: 'DeviceInfo | take 5', Timespan: 'P7D' }),
    });
  });

  it('builds server-side incident filters and returns an opaque continuation token', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          value: [{ id: 'incident-1', severity: 'high' }],
          '@odata.nextLink':
            'https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=secret',
        }),
        { status: 200 },
      ),
    );
    const http = new MicrosoftHttpClient(
      'https://graph.microsoft.com',
      { getToken: () => Promise.resolve('access-token'), invalidate: vi.fn() },
      new CountingRateLimiter(),
      { fetch: fetchMock },
    );
    const graph = new GraphClient(
      http,
      new ContinuationTokenStore(['https://graph.microsoft.com'], {
        createId: () => '00000000-0000-4000-8000-000000000001',
      }),
    );

    const page = await graph.listIncidents({
      status: 'active',
      assignedTo: "o'hare@example.com",
      createdAfter: '2026-08-01T00:00:00Z',
      top: 25,
    });

    const requestUrl = fetchMock.mock.calls[0]?.[0] as URL;
    expect(requestUrl.searchParams.get('$top')).toBe('25');
    expect(requestUrl.searchParams.get('$filter')).toBe(
      "status eq 'active' and assignedTo eq 'o''hare@example.com' and createdDateTime ge 2026-08-01T00:00:00Z",
    );
    expect(page.continuationToken).toBe('00000000-0000-4000-8000-000000000001');
    expect(JSON.stringify(page)).not.toContain('$skiptoken=secret');
  });

  it('redeems an opaque continuation token without accepting a client URL', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(JSON.stringify({ value: [] }), { status: 200 }));
    const http = new MicrosoftHttpClient(
      'https://graph.microsoft.com',
      { getToken: () => Promise.resolve('access-token'), invalidate: vi.fn() },
      new CountingRateLimiter(),
      { fetch: fetchMock },
    );
    const continuations = new ContinuationTokenStore(['https://graph.microsoft.com'], {
      createId: () => '00000000-0000-4000-8000-000000000001',
    });
    const token = continuations.issue(
      'https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=server-value',
    );

    await new GraphClient(http, continuations).listAlerts({ top: 10, continuationToken: token });

    expect(fetchMock.mock.calls[0]?.[0]).toEqual(
      new URL('https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=server-value'),
    );
  });
});
