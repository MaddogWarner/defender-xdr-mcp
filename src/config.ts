import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { accessSync, constants, readFileSync } from 'node:fs';

import { z } from 'zod';

const guid = z.string().uuid('must be a GUID');
const positiveInteger = (fallback: number) => z.coerce.number().int().positive().default(fallback);
const boundedPositiveInteger = (fallback: number, maximum: number) =>
  z.coerce.number().int().positive().max(maximum).default(fallback);
const ISO_DURATION_PATTERN = /^P(?=\d|T\d)(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$/;
const duration = (fallback: string) =>
  z
    .string()
    .regex(ISO_DURATION_PATTERN, {
      message: 'must be an ISO 8601 duration',
    })
    .default(fallback);

const environmentSchema = z
  .object({
    DXM_TENANT_ID: guid,
    DXM_CLIENT_ID: guid,
    DXM_TRANSPORT: z.enum(['stdio', 'http']).default('stdio'),
    DXM_MDE_REGION: z.enum(['au', 'us', 'eu', 'uk', 'swa', 'ina', 'aea']).optional(),
    DXM_DEFAULT_TIMESPAN: duration('P7D'),
    DXM_MAX_TIMESPAN: duration('P30D'),
    DXM_MAX_ROWS: boundedPositiveInteger(1000, 100_000),
    DXM_MAX_RESPONSE_BYTES: boundedPositiveInteger(262144, 50_000_000),
    DXM_HUNTING_RPM: positiveInteger(40),
    DXM_HUNTING_RPH: positiveInteger(1200),
    DXM_MDE_RPM: positiveInteger(45),
    DXM_MDE_RPH: positiveInteger(1350),
    DXM_AUDIT_LOG_PATH: z.string().min(1).default('./audit.jsonl'),
    DXM_AUDIT_MAX_MB: positiveInteger(256),
    DXM_AUDIT_KEEP: positiveInteger(5),
    DXM_HTTP_HOST: z.string().min(1).default('127.0.0.1'),
    DXM_HTTP_PORT: z.coerce.number().int().min(1).max(65535).default(3020),
    DXM_PUBLIC_URL: z.url().optional(),
    DXM_CLIENT_SECRET: z.string().min(1).optional(),
    DXM_CLIENT_CERT_PATH: z.string().min(1).optional(),
  })
  .superRefine((value, context) => {
    const maximumSeconds = parseIsoDurationSeconds(value.DXM_MAX_TIMESPAN);
    const defaultSeconds = parseIsoDurationSeconds(value.DXM_DEFAULT_TIMESPAN);
    if (maximumSeconds !== null && maximumSeconds > 30 * 24 * 60 * 60) {
      context.addIssue({
        code: 'custom',
        path: ['DXM_MAX_TIMESPAN'],
        message: 'must not exceed P30D',
      });
    }
    if (defaultSeconds !== null && maximumSeconds !== null && defaultSeconds > maximumSeconds) {
      context.addIssue({
        code: 'custom',
        path: ['DXM_DEFAULT_TIMESPAN'],
        message: 'must not exceed DXM_MAX_TIMESPAN',
      });
    }

    if (
      value.DXM_TRANSPORT === 'http' &&
      value.DXM_CLIENT_SECRET === undefined &&
      value.DXM_CLIENT_CERT_PATH === undefined
    ) {
      context.addIssue({
        code: 'custom',
        path: ['DXM_CLIENT_SECRET'],
        message: 'or DXM_CLIENT_CERT_PATH is required when DXM_TRANSPORT=http',
      });
    }

    if (value.DXM_TRANSPORT === 'http' && value.DXM_PUBLIC_URL === undefined) {
      context.addIssue({
        code: 'custom',
        path: ['DXM_PUBLIC_URL'],
        message: 'is required when DXM_TRANSPORT=http',
      });
    }

    if (value.DXM_PUBLIC_URL !== undefined) {
      validatePublicUrl(value.DXM_PUBLIC_URL, context);
    }

    if (value.DXM_TRANSPORT === 'http' && value.DXM_CLIENT_CERT_PATH !== undefined) {
      validateCertificateFile(value.DXM_CLIENT_CERT_PATH, context);
    }
  });

export function parseIsoDurationSeconds(value: string): number | null {
  const match = ISO_DURATION_PATTERN.exec(value);
  if (match === null) {
    return null;
  }
  const components = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(value);
  if (components === null) {
    return null;
  }
  const days = Number(components[1] ?? 0);
  const hours = Number(components[2] ?? 0);
  const minutes = Number(components[3] ?? 0);
  const seconds = Number(components[4] ?? 0);
  return days * 86_400 + hours * 3_600 + minutes * 60 + seconds;
}

export type AppConfig = Readonly<{
  tenantId: string;
  clientId: string;
  transport: 'stdio' | 'http';
  mdeRegion?: 'au' | 'us' | 'eu' | 'uk' | 'swa' | 'ina' | 'aea';
  defaultTimespan: string;
  maxTimespan: string;
  maxRows: number;
  maxResponseBytes: number;
  huntingRpm: number;
  huntingRph: number;
  mdeRpm: number;
  mdeRph: number;
  auditLogPath: string;
  auditMaxMb: number;
  auditKeep: number;
  httpHost: string;
  httpPort: number;
  publicUrl?: string;
  clientSecret?: string;
  clientCertPath?: string;
}>;

function validateCertificateFile(path: string, context: z.RefinementCtx): void {
  try {
    accessSync(path, constants.R_OK);
    const pem = readFileSync(path, 'utf8');
    const certificate = new X509Certificate(pem);
    const privateKey = createPrivateKey(pem);
    const certificateKey = certificate.publicKey.export({ type: 'spki', format: 'der' });
    const privatePublicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });

    if (!certificateKey.equals(privatePublicKey)) {
      throw new Error('certificate and private key do not match');
    }
  } catch (error: unknown) {
    context.addIssue({
      code: 'custom',
      path: ['DXM_CLIENT_CERT_PATH'],
      message: `must be a readable PEM containing a matching certificate and unencrypted private key (${error instanceof Error ? error.message : 'invalid file'})`,
    });
  }
}

function validatePublicUrl(value: string, context: z.RefinementCtx): void {
  const url = new URL(value);
  const loopback =
    url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    context.addIssue({
      code: 'custom',
      path: ['DXM_PUBLIC_URL'],
      message: 'must use https, except for an explicit loopback URL',
    });
  }
  if (
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.pathname !== '/'
  ) {
    context.addIssue({
      code: 'custom',
      path: ['DXM_PUBLIC_URL'],
      message: 'must be an origin URL without credentials, path, query, or fragment',
    });
  }
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  const result = environmentSchema.safeParse(environment);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `${issue.path.join('.') || 'environment'}: ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid configuration: ${details}`);
  }

  const value = result.data;
  return {
    tenantId: value.DXM_TENANT_ID,
    clientId: value.DXM_CLIENT_ID,
    transport: value.DXM_TRANSPORT,
    ...(value.DXM_MDE_REGION === undefined ? {} : { mdeRegion: value.DXM_MDE_REGION }),
    defaultTimespan: value.DXM_DEFAULT_TIMESPAN,
    maxTimespan: value.DXM_MAX_TIMESPAN,
    maxRows: value.DXM_MAX_ROWS,
    maxResponseBytes: value.DXM_MAX_RESPONSE_BYTES,
    huntingRpm: value.DXM_HUNTING_RPM,
    huntingRph: value.DXM_HUNTING_RPH,
    mdeRpm: value.DXM_MDE_RPM,
    mdeRph: value.DXM_MDE_RPH,
    auditLogPath: value.DXM_AUDIT_LOG_PATH,
    auditMaxMb: value.DXM_AUDIT_MAX_MB,
    auditKeep: value.DXM_AUDIT_KEEP,
    httpHost: value.DXM_HTTP_HOST,
    httpPort: value.DXM_HTTP_PORT,
    ...(value.DXM_PUBLIC_URL === undefined ? {} : { publicUrl: value.DXM_PUBLIC_URL }),
    ...(value.DXM_CLIENT_SECRET === undefined ? {} : { clientSecret: value.DXM_CLIENT_SECRET }),
    ...(value.DXM_CLIENT_CERT_PATH === undefined
      ? {}
      : { clientCertPath: value.DXM_CLIENT_CERT_PATH }),
  };
}
