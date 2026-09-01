import { describe, expect, it, vi } from 'vitest';

import { ContinuationTokenStore } from '../../src/clients/continuationTokens.js';
import { MicrosoftHttpClient } from '../../src/clients/http.js';
import { MdeClient } from '../../src/clients/mde.js';
import { CountingRateLimiter } from '../helpers/rateLimiter.js';

function createMde(fetchMock: typeof fetch): MdeClient {
  const origin = 'https://au.api.security.microsoft.com';
  return new MdeClient(
    new MicrosoftHttpClient(
      origin,
      { getToken: () => Promise.resolve('mde-token'), invalidate: vi.fn() },
      new CountingRateLimiter(),
      { fetch: fetchMock },
    ),
    new ContinuationTokenStore([origin]),
  );
}

describe('MdeClient', () => {
  it('uses the MDE vulnerability endpoint with server-side OData filters', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          value: [
            {
              id: 'CVE-2026-1234',
              publicExploit: true,
              exploitVerified: false,
              exploitInKit: false,
              exploitTypes: ['Remote'],
              epss: 0.8,
            },
          ],
        }),
      ),
    );

    await createMde(fetchMock).listVulnerabilities({
      severity: 'Critical',
      cveId: 'CVE-2026-1234',
      top: 50,
    });

    const url = fetchMock.mock.calls[0]?.[0] as URL;
    expect(url.origin).toBe('https://au.api.security.microsoft.com');
    expect(url.pathname).toBe('/api/vulnerabilities');
    expect(url.searchParams.get('$top')).toBe('50');
    expect(url.searchParams.get('$filter')).toBe(
      "severity eq 'Critical' and id eq 'CVE-2026-1234'",
    );
    expect(url.search).not.toContain('exploit');
  });

  it('gets a device and its discovered vulnerabilities from fixed read-only paths', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ id: 'machine/with spaces', computerDnsName: 'host.example' }),
        ),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: [{ id: 'CVE-2026-1234' }] })));

    const result = await createMde(fetchMock).getDevice('machine/with spaces');

    expect(fetchMock.mock.calls.map((call) => (call[0] as URL).pathname)).toEqual([
      '/api/machines/machine%2Fwith%20spaces',
      '/api/machines/machine%2Fwith%20spaces/vulnerabilities',
    ]);
    expect(result.vulnerabilities).toEqual([{ id: 'CVE-2026-1234' }]);
  });
});
