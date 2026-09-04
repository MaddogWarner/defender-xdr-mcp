import { describe, expect, it, vi } from 'vitest';

import { ResourceInteractionRequiredError } from '../../src/auth/msal.js';
import { OnBehalfOfExchangeError } from '../../src/auth/obo.js';
import { ContinuationTokenError } from '../../src/clients/continuationTokens.js';
import { MicrosoftApiError } from '../../src/clients/http.js';
import { ToolPipeline, type ToolAuditEntry } from '../../src/tools/pipeline.js';

const shapeConfig = { maxRows: 100, maxResponseBytes: 16_384 };

describe('ToolPipeline', () => {
  it('centrally shapes output and audits complete success metadata', async () => {
    const entries: ToolAuditEntry[] = [];
    const pipeline = new ToolPipeline(
      () => 'analyst@example.com',
      (entry) => {
        entries.push(entry);
        return Promise.resolve();
      },
      shapeConfig,
    );
    const outcome = await pipeline.run({
      tool: 'run_hunting_query',
      args: { query: 'DeviceInfo' },
      input: 'DeviceInfo',
      validate: (query) => ({ ok: true, value: query, notices: ['clamped'] }),
      execute: () => Promise.resolve([{ DeviceName: 'host.example' }]),
    });

    expect(outcome).toMatchObject({ ok: true, output: { notices: ['clamped'], rowCount: 1 } });
    expect(outcome.ok && outcome.output.text).toContain('BEGIN UNTRUSTED DEFENDER TELEMETRY');
    expect(entries[0]).toMatchObject({
      upn: 'analyst@example.com',
      tool: 'run_hunting_query',
      args: { query: 'DeviceInfo' },
      rowCount: 1,
      status: 'success',
    });
  });

  it('audits Microsoft error codes before propagating failures', async () => {
    const audit = vi.fn<(_entry: ToolAuditEntry) => Promise<void>>().mockResolvedValue(undefined);
    const pipeline = new ToolPipeline(() => 'analyst@example.com', audit, shapeConfig);
    await expect(
      pipeline.run({
        tool: 'run_hunting_query',
        args: { query: 'DeviceInfo' },
        input: 'DeviceInfo',
        validate: (query) => ({ ok: true, value: query, notices: [] }),
        execute: () =>
          Promise.reject(
            new MicrosoftApiError({ code: 'Forbidden', message: 'Denied', retryable: false }),
          ),
      }),
    ).rejects.toBeInstanceOf(MicrosoftApiError);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ error: { code: 'Forbidden' }, status: 'error' }),
    );
  });

  it('preserves validation_failed for a validator rejection', async () => {
    const audit = vi.fn<(_entry: ToolAuditEntry) => Promise<void>>().mockResolvedValue(undefined);
    const pipeline = new ToolPipeline(() => undefined, audit, shapeConfig);
    await expect(
      pipeline.run({
        tool: 'run_hunting_query',
        args: { query: '' },
        input: '',
        validate: () => ({ ok: false, reason: 'The KQL query must not be empty.' }),
        execute: () => Promise.resolve([]),
      }),
    ).resolves.toEqual({ ok: false, reason: 'The KQL query must not be empty.' });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ error: { code: 'validation_failed' }, status: 'error' }),
    );
  });

  it('preserves validation_error for a throwing validator', async () => {
    const audit = vi.fn<(_entry: ToolAuditEntry) => Promise<void>>().mockResolvedValue(undefined);
    const pipeline = new ToolPipeline(() => undefined, audit, shapeConfig);
    const failure = new Error('validator crashed');
    await expect(
      pipeline.run({
        tool: 'run_hunting_query',
        args: { query: 'DeviceInfo' },
        input: 'DeviceInfo',
        validate: () => {
          throw failure;
        },
        execute: () => Promise.resolve([]),
      }),
    ).rejects.toBe(failure);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ error: { code: 'validation_error' }, status: 'error' }),
    );
  });

  it('audits asynchronous authentication failures inside validation', async () => {
    const audit = vi.fn<(_entry: ToolAuditEntry) => Promise<void>>().mockResolvedValue(undefined);
    const pipeline = new ToolPipeline(() => undefined, audit, shapeConfig);
    const failure = new Error('keystore unavailable');
    await expect(
      pipeline.run({
        tool: 'list_incidents',
        args: {},
        input: undefined,
        validate: () => Promise.reject(failure),
        execute: () => Promise.resolve([]),
      }),
    ).rejects.toBe(failure);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ error: { code: 'validation_error' }, status: 'error' }),
    );
  });

  it('returns a model-readable reason for an expired continuation token after auditing it', async () => {
    const audit = vi.fn<(_entry: ToolAuditEntry) => Promise<void>>().mockResolvedValue(undefined);
    const pipeline = new ToolPipeline(() => undefined, audit, shapeConfig);
    await expect(
      pipeline.run({
        tool: 'list_incidents',
        args: { continuationToken: 'expired' },
        input: undefined,
        validate: () => ({ ok: true, value: undefined, notices: [] }),
        execute: () => Promise.reject(new ContinuationTokenError()),
      }),
    ).resolves.toEqual({
      ok: false,
      reason: 'That continuation token expired or was already used. Re-run the original query.',
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ error: { code: 'ContinuationTokenError' }, status: 'error' }),
    );
  });

  it('returns an explicit sign-in action when silent reacquisition is interaction-required', async () => {
    const audit = vi.fn<(_entry: ToolAuditEntry) => Promise<void>>().mockResolvedValue(undefined);
    const pipeline = new ToolPipeline(() => undefined, audit, shapeConfig);
    await expect(
      pipeline.run({
        tool: 'list_vulnerabilities',
        args: {},
        input: undefined,
        validate: () => ({ ok: true, value: undefined, notices: [] }),
        execute: () => Promise.reject(new ResourceInteractionRequiredError('mde')),
      }),
    ).resolves.toEqual({
      ok: false,
      reason:
        'Defender for Endpoint requires interactive sign-in. Call get_connection_status to sign in, then retry.',
    });
  });

  it('returns and audits an OBO failure raised while validating resource access', async () => {
    const audit = vi.fn<(_entry: ToolAuditEntry) => Promise<void>>().mockResolvedValue(undefined);
    const pipeline = new ToolPipeline(() => 'analyst@example.com', audit, shapeConfig);
    const failure = new OnBehalfOfExchangeError('mde', 'invalid_grant');

    await expect(
      pipeline.run({
        tool: 'list_devices',
        args: {},
        input: undefined,
        validate: () => Promise.reject(failure),
        execute: () => Promise.resolve([]),
      }),
    ).resolves.toEqual({ ok: false, reason: failure.message });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ error: { code: 'validation_error' }, status: 'error' }),
    );
  });

  it('returns and audits an OBO failure raised while executing a tool', async () => {
    const audit = vi.fn<(_entry: ToolAuditEntry) => Promise<void>>().mockResolvedValue(undefined);
    const pipeline = new ToolPipeline(() => 'analyst@example.com', audit, shapeConfig);
    const failure = new OnBehalfOfExchangeError('graph', 'unauthorized_client');

    await expect(
      pipeline.run({
        tool: 'list_incidents',
        args: {},
        input: undefined,
        validate: () => ({ ok: true, value: undefined, notices: [] }),
        execute: () => Promise.reject(failure),
      }),
    ).resolves.toEqual({ ok: false, reason: failure.message });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        error: { code: 'OnBehalfOfExchangeError' },
        status: 'error',
      }),
    );
  });

  it('fails closed when a successful call cannot be audited', async () => {
    const auditFailure = new Error('ENOSPC');
    const audit = vi
      .fn<(_entry: ToolAuditEntry) => Promise<void>>()
      .mockRejectedValue(auditFailure);
    const pipeline = new ToolPipeline(() => undefined, audit, shapeConfig);
    await expect(
      pipeline.run({
        tool: 'get_incident',
        args: { id: '1' },
        input: '1',
        validate: (id) => ({ ok: true, value: id, notices: [] }),
        execute: () => Promise.resolve({ id: '1' }),
      }),
    ).rejects.toBe(auditFailure);
    expect(audit).toHaveBeenCalledOnce();
  });
});
