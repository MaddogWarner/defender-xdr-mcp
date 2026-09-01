import { ResourceInteractionRequiredError } from '../auth/msal.js';
import type { AuditEntry } from '../audit/log.js';
import { ContinuationTokenError } from '../clients/continuationTokens.js';
import { MicrosoftApiError } from '../clients/http.js';
import {
  shapeOutput,
  type OutputShapeConfig,
  type ShapedOutput,
} from '../guardrails/outputShaper.js';
import { LocalRateLimitError } from '../guardrails/rateLimiter.js';

export type ToolValidation<T> =
  { ok: true; value: T; notices: readonly string[] } | { ok: false; reason: string };

export type ShapedToolOutput = ShapedOutput;
export type ToolAuditEntry = AuditEntry;

interface ToolInvocation<TInput, TValidated, TRaw> {
  tool: string;
  args: Readonly<Record<string, unknown>>;
  input: TInput;
  validate(input: TInput): ToolValidation<TValidated> | Promise<ToolValidation<TValidated>>;
  execute(input: TValidated): Promise<TRaw>;
}

export type ToolPipelineResult =
  { ok: true; output: ShapedToolOutput } | { ok: false; reason: string };

export class ToolPipeline {
  readonly #getUpn: () => string | undefined;
  readonly #audit: (entry: ToolAuditEntry) => Promise<void>;
  readonly #shapeConfig: OutputShapeConfig;

  constructor(
    getUpn: () => string | undefined,
    audit: (entry: ToolAuditEntry) => Promise<void>,
    shapeConfig: OutputShapeConfig,
  ) {
    this.#getUpn = getUpn;
    this.#audit = audit;
    this.#shapeConfig = shapeConfig;
  }

  async run<TInput, TValidated, TRaw>(
    invocation: ToolInvocation<TInput, TValidated, TRaw>,
  ): Promise<ToolPipelineResult> {
    const started = Date.now();
    let validation: ToolValidation<TValidated>;
    try {
      validation = await invocation.validate(invocation.input);
    } catch (error: unknown) {
      await this.#audit({
        ts: new Date().toISOString(),
        upn: this.#getUpn() ?? null,
        tool: invocation.tool,
        args: invocation.args,
        rowCount: 0,
        durationMs: Date.now() - started,
        status: 'error',
        error: { code: 'validation_error' },
      });
      const reason = correctableReason(error);
      if (reason !== undefined) {
        return { ok: false, reason };
      }
      throw error;
    }
    if (!validation.ok) {
      await this.#audit({
        ts: new Date().toISOString(),
        upn: this.#getUpn() ?? null,
        tool: invocation.tool,
        args: invocation.args,
        rowCount: 0,
        durationMs: Date.now() - started,
        status: 'error',
        error: { code: 'validation_failed' },
      });
      return validation;
    }

    let output: ShapedToolOutput;
    try {
      const raw = await invocation.execute(validation.value);
      output = shapeOutput(raw, this.#shapeConfig, validation.notices);
    } catch (error: unknown) {
      const code = errorCode(error);
      await this.#audit({
        ts: new Date().toISOString(),
        upn: this.#getUpn() ?? null,
        tool: invocation.tool,
        args: invocation.args,
        rowCount: 0,
        durationMs: Date.now() - started,
        status: 'error',
        error: { ...(code === undefined ? {} : { code }) },
      });
      const reason = correctableReason(error);
      if (reason !== undefined) {
        return { ok: false, reason };
      }
      throw error;
    }
    await this.#auditSuccess(invocation, output.rowCount, started);
    return { ok: true, output };
  }

  #auditSuccess<TInput, TValidated, TRaw>(
    invocation: ToolInvocation<TInput, TValidated, TRaw>,
    rowCount: number,
    started: number,
  ): Promise<void> {
    return this.#audit({
      ts: new Date().toISOString(),
      upn: this.#getUpn() ?? null,
      tool: invocation.tool,
      args: invocation.args,
      rowCount,
      durationMs: Date.now() - started,
      status: 'success',
    });
  }
}

function correctableReason(error: unknown): string | undefined {
  if (
    error instanceof ContinuationTokenError ||
    error instanceof ResourceInteractionRequiredError ||
    error instanceof LocalRateLimitError
  ) {
    return error.message;
  }
  return undefined;
}

function errorCode(error: unknown): string | undefined {
  if (error instanceof MicrosoftApiError) {
    return error.details.code;
  }
  return error instanceof Error ? error.name : undefined;
}
