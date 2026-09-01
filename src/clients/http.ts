import { z } from 'zod';

export type ApiFamily = 'hunting' | 'graph-other' | 'mde';
export interface TokenProvider {
  getToken(): Promise<string>;
  invalidate(): void;
}

export interface RateLimiterState {
  attempts: Readonly<Record<ApiFamily, number>>;
  windows?: Readonly<
    Record<ApiFamily, { readonly minuteRemaining: number; readonly hourRemaining: number }>
  >;
}

export interface RequestRateLimiter {
  acquire(family: ApiFamily): Promise<void>;
  state(): RateLimiterState;
}

export interface MicrosoftErrorShape {
  code: string;
  message: string;
  retryable: boolean;
}

export class MicrosoftApiError extends Error {
  readonly details: MicrosoftErrorShape;

  constructor(details: MicrosoftErrorShape) {
    super(details.message);
    this.name = 'MicrosoftApiError';
    this.details = details;
  }
}

interface RequestOptions<T> {
  path: string;
  method: 'GET' | 'POST';
  family: ApiFamily;
  schema: z.ZodType<T>;
  body?: unknown;
  timeoutMs?: number;
}

interface HttpClientOptions {
  fetch?: typeof fetch;
  sleep?: (milliseconds: number) => Promise<void>;
  random?: () => number;
}

const errorBodySchema = z.looseObject({
  code: z.string().optional(),
  message: z.string().optional(),
  error: z
    .looseObject({
      code: z.string().optional(),
      message: z.string().optional(),
    })
    .optional(),
});

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RETRIES = 3;
const MAX_RETRY_DELAY_MS = 60_000;
const MAX_CUMULATIVE_RETRY_WAIT_MS = 120_000;

export class MicrosoftHttpClient {
  readonly #baseUrl: URL;
  readonly #tokenProvider: TokenProvider;
  readonly #rateLimiter: RequestRateLimiter;
  readonly #fetch: typeof fetch;
  readonly #sleep: (milliseconds: number) => Promise<void>;
  readonly #random: () => number;

  constructor(
    baseUrl: string,
    tokenProvider: TokenProvider,
    rateLimiter: RequestRateLimiter,
    options: HttpClientOptions = {},
  ) {
    this.#baseUrl = new URL(baseUrl);
    this.#tokenProvider = tokenProvider;
    this.#rateLimiter = rateLimiter;
    this.#fetch = options.fetch ?? fetch;
    this.#sleep =
      options.sleep ??
      ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.#random = options.random ?? Math.random;
  }

  async request<T>(options: RequestOptions<T>): Promise<T> {
    const url = this.#resolvePath(options.path);
    let cumulativeRetryWait = 0;

    let retriedAfterUnauthorised = false;
    for (let retry = 0; ; retry += 1) {
      await this.#rateLimiter.acquire(options.family);
      const token = await this.#tokenProvider.getToken();

      let response: Response;
      try {
        response = await this.#fetch(url, {
          method: options.method,
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/json',
            ...(options.body === undefined
              ? {}
              : { 'Content-Type': 'application/json; charset=utf-8' }),
          },
          ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
          signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
        });
      } catch (error: unknown) {
        if (
          error instanceof Error &&
          (error.name === 'AbortError' || error.name === 'TimeoutError')
        ) {
          throw new MicrosoftApiError({
            code: 'request_timeout',
            message: `Microsoft API request timed out after ${options.timeoutMs ?? DEFAULT_TIMEOUT_MS} ms`,
            retryable: true,
          });
        }
        throw error;
      }

      if ((response.status === 429 || response.status === 503) && retry < MAX_RETRIES) {
        const remainingWait = MAX_CUMULATIVE_RETRY_WAIT_MS - cumulativeRetryWait;
        if (remainingWait <= 0) {
          throw new MicrosoftApiError(await mapMicrosoftError(response));
        }
        const delay = Math.min(
          this.#retryDelay(response.headers.get('Retry-After'), retry),
          MAX_RETRY_DELAY_MS,
          remainingWait,
        );
        await this.#sleep(delay);
        cumulativeRetryWait += delay;
        continue;
      }

      if (response.status === 401 && !retriedAfterUnauthorised) {
        this.#tokenProvider.invalidate();
        retriedAfterUnauthorised = true;
        continue;
      }

      if (!response.ok) {
        throw new MicrosoftApiError(await mapMicrosoftError(response));
      }

      let body: unknown;
      try {
        body = await response.json();
      } catch {
        throw new MicrosoftApiError({
          code: 'malformed_response',
          message: 'Microsoft API returned a non-JSON response',
          retryable: false,
        });
      }

      const parsed = options.schema.safeParse(body);
      if (!parsed.success) {
        throw new MicrosoftApiError({
          code: 'malformed_response',
          message: 'Microsoft API response did not match the expected schema',
          retryable: false,
        });
      }
      return parsed.data;
    }
  }

  #resolvePath(path: string): URL {
    if (!path.startsWith('/') || path.startsWith('//')) {
      throw new Error('Microsoft API request path must be an absolute path on the configured host');
    }
    const url = new URL(path, this.#baseUrl);
    if (url.origin !== this.#baseUrl.origin) {
      throw new Error('Microsoft API request path resolved outside the configured host');
    }
    return url;
  }

  #retryDelay(retryAfter: string | null, retry: number): number {
    if (retryAfter !== null) {
      const seconds = Number(retryAfter);
      if (Number.isFinite(seconds) && seconds >= 0) {
        return seconds * 1000;
      }
      const date = Date.parse(retryAfter);
      if (Number.isFinite(date)) {
        return Math.max(0, date - Date.now());
      }
    }
    return 500 * 2 ** retry + Math.floor(this.#random() * 250);
  }
}

async function mapMicrosoftError(response: Response): Promise<MicrosoftErrorShape> {
  let parsed: z.infer<typeof errorBodySchema> | undefined;
  try {
    const candidate = errorBodySchema.safeParse(await response.json());
    parsed = candidate.success ? candidate.data : undefined;
  } catch {
    parsed = undefined;
  }

  const message =
    parsed?.error?.message ?? parsed?.message ?? `Microsoft API returned HTTP ${response.status}`;
  return {
    code: parsed?.error?.code ?? parsed?.code ?? `http_${response.status}`,
    message: message.slice(0, 500),
    retryable: response.status === 429 || response.status === 503 || response.status >= 500,
  };
}
