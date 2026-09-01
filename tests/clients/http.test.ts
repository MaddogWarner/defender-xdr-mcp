import { z } from 'zod';
import { describe, expect, it, vi } from 'vitest';

import { MicrosoftHttpClient } from '../../src/clients/http.js';
import { DualWindowRateLimiter } from '../../src/guardrails/rateLimiter.js';
import { CountingRateLimiter } from '../helpers/rateLimiter.js';

const responseSchema = z.object({ value: z.string() });

function createClient(fetchMock: typeof fetch, rateLimiter = new CountingRateLimiter()) {
  const tokenProvider = {
    getToken: vi.fn(() => Promise.resolve('access-token')),
    invalidate: vi.fn(),
  };
  return {
    client: new MicrosoftHttpClient('https://graph.microsoft.com', tokenProvider, rateLimiter, {
      fetch: fetchMock,
      sleep: () => Promise.resolve(),
      random: () => 0,
    }),
    rateLimiter,
    tokenProvider,
  };
}

describe('MicrosoftHttpClient', () => {
  it('injects bearer authentication and validates a successful response', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(JSON.stringify({ value: 'ok' }), { status: 200 }));
    const { client } = createClient(fetchMock);

    const result = await client.request({
      path: '/v1.0/security/test',
      method: 'GET',
      family: 'graph-other',
      schema: responseSchema,
    });

    expect(result).toEqual({ value: 'ok' });
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({
      Authorization: 'Bearer access-token',
    });
  });

  it('honours Retry-After and charges retries to the limiter', async () => {
    const sleep = vi.fn<(milliseconds: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('{}', { status: 429, headers: { 'Retry-After': '2' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: 'ok' }), { status: 200 }));
    const rateLimiter = new DualWindowRateLimiter({
      hunting: { requestsPerMinute: 10, requestsPerHour: 100 },
      'graph-other': { requestsPerMinute: 10, requestsPerHour: 100 },
      mde: { requestsPerMinute: 10, requestsPerHour: 100 },
    });
    const client = new MicrosoftHttpClient(
      'https://graph.microsoft.com',
      { getToken: () => Promise.resolve('access-token'), invalidate: vi.fn() },
      rateLimiter,
      { fetch: fetchMock, sleep, random: () => 0 },
    );

    await client.request({
      path: '/v1.0/security/runHuntingQuery',
      method: 'POST',
      family: 'hunting',
      schema: responseSchema,
      body: { Query: 'DeviceInfo | take 5' },
    });

    expect(sleep).toHaveBeenCalledWith(2000);
    expect(rateLimiter.state().attempts.hunting).toBe(2);
  });

  it('retries immediately when Retry-After is zero', async () => {
    const sleep = vi.fn<(milliseconds: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('{}', { status: 429, headers: { 'Retry-After': '0' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: 'ok' }), { status: 200 }));
    const rateLimiter = new CountingRateLimiter();
    const client = new MicrosoftHttpClient(
      'https://graph.microsoft.com',
      { getToken: () => Promise.resolve('access-token'), invalidate: vi.fn() },
      rateLimiter,
      { fetch: fetchMock, sleep, random: () => 0 },
    );

    await expect(
      client.request({
        path: '/v1.0/security/test',
        method: 'GET',
        family: 'graph-other',
        schema: responseSchema,
      }),
    ).resolves.toEqual({ value: 'ok' });

    expect(sleep).toHaveBeenCalledWith(0);
    expect(rateLimiter.state().attempts['graph-other']).toBe(2);
  });

  it('clamps individual and cumulative Retry-After waits', async () => {
    const sleep = vi.fn<(milliseconds: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'Busy', message: 'Try later' } }), {
        status: 503,
        headers: { 'Retry-After': '86400' },
      }),
    );
    const rateLimiter = new CountingRateLimiter();
    const client = new MicrosoftHttpClient(
      'https://graph.microsoft.com',
      { getToken: () => Promise.resolve('access-token'), invalidate: vi.fn() },
      rateLimiter,
      { fetch: fetchMock, sleep, random: () => 0 },
    );

    await expect(
      client.request({
        path: '/v1.0/security/test',
        method: 'GET',
        family: 'graph-other',
        schema: responseSchema,
      }),
    ).rejects.toMatchObject({ details: { code: 'Busy', retryable: true } });

    expect(sleep.mock.calls).toEqual([[60_000], [60_000]]);
    expect(rateLimiter.state().attempts['graph-other']).toBe(3);
  });

  it('stops after three retries and returns a compact Microsoft error', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'TooManyRequests', message: 'Slow down' } }), {
        status: 429,
      }),
    );
    const { client, rateLimiter } = createClient(fetchMock);

    const failure = client.request({
      path: '/v1.0/security/test',
      method: 'GET',
      family: 'graph-other',
      schema: responseSchema,
    });

    await expect(failure).rejects.toMatchObject({
      details: { code: 'TooManyRequests', message: 'Slow down', retryable: true },
    });
    expect(rateLimiter.state().attempts['graph-other']).toBe(4);
  });

  it('rejects malformed Microsoft responses', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(JSON.stringify({ unexpected: true }), { status: 200 }));
    const { client } = createClient(fetchMock);

    await expect(
      client.request({
        path: '/v1.0/security/test',
        method: 'GET',
        family: 'graph-other',
        schema: responseSchema,
      }),
    ).rejects.toMatchObject({ details: { code: 'malformed_response' } });
  });

  it('invalidates and retries once after a 401', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('{}', { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: 'ok' }), { status: 200 }));
    const { client, tokenProvider } = createClient(fetchMock);

    await expect(
      client.request({
        path: '/v1.0/security/test',
        method: 'GET',
        family: 'graph-other',
        schema: responseSchema,
      }),
    ).resolves.toEqual({ value: 'ok' });

    expect(tokenProvider.invalidate).toHaveBeenCalledOnce();
    expect(tokenProvider.getToken).toHaveBeenCalledTimes(2);
  });

  it('returns a repeated 401 without retrying again', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response('{}', { status: 401 }));
    const { client, tokenProvider } = createClient(fetchMock);

    await expect(
      client.request({
        path: '/v1.0/security/test',
        method: 'GET',
        family: 'graph-other',
        schema: responseSchema,
      }),
    ).rejects.toMatchObject({ details: { code: 'http_401', retryable: false } });

    expect(tokenProvider.invalidate).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects paths that could change the configured host', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    const { client } = createClient(fetchMock);

    await expect(
      client.request({
        path: '//attacker.example/path',
        method: 'GET',
        family: 'graph-other',
        schema: responseSchema,
      }),
    ).rejects.toThrow(/configured host/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
