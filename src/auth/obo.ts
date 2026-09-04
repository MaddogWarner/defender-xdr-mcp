import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  ConfidentialClientApplication,
  type AuthenticationResult,
  type IConfidentialClientApplication,
  type OnBehalfOfRequest,
} from '@azure/msal-node';

import type { AppConfig } from '../config.js';
import type { AccessTokenContext, AuthProvider, ConnectionStatus, TokenResource } from './msal.js';
import { GRAPH_SCOPES, MDE_TOKEN_SCOPES } from './scopes.js';

const EXPIRY_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_MAXIMUM_CACHE_ENTRIES = 512;

interface OboApplication {
  acquireTokenOnBehalfOf(request: OnBehalfOfRequest): Promise<AuthenticationResult | null>;
}

interface CachedToken {
  context: AccessTokenContext;
  usableUntilMs: number;
}

export class OnBehalfOfExchangeError extends Error {
  readonly resource: TokenResource;
  readonly errorCode: string;

  constructor(resource: TokenResource, errorCode: string) {
    super(exchangeFailureMessage(resource, errorCode));
    this.name = 'OnBehalfOfExchangeError';
    this.resource = resource;
    this.errorCode = errorCode;
  }
}

export class OboTokenCache {
  readonly #maximumEntries: number;
  readonly #tokens = new Map<string, CachedToken>();
  readonly #pending = new Map<string, Promise<AccessTokenContext>>();

  constructor(maximumEntries: number = DEFAULT_MAXIMUM_CACHE_ENTRIES) {
    this.#maximumEntries = Math.max(1, maximumEntries);
  }

  get size(): number {
    return this.#tokens.size;
  }

  get(key: string, nowMs: number): AccessTokenContext | undefined {
    const cached = this.#tokens.get(key);
    if (cached === undefined) {
      return undefined;
    }
    if (cached.usableUntilMs <= nowMs) {
      this.#tokens.delete(key);
      return undefined;
    }
    return cached.context;
  }

  set(key: string, context: AccessTokenContext, usableUntilMs: number, nowMs: number): void {
    this.#removeExpired(nowMs);
    if (usableUntilMs <= nowMs) return;
    this.#tokens.delete(key);
    while (this.#tokens.size >= this.#maximumEntries) {
      const oldest = this.#tokens.keys().next().value;
      if (oldest === undefined) break;
      this.#tokens.delete(oldest);
    }
    this.#tokens.set(key, { context, usableUntilMs });
  }

  delete(key: string): void {
    this.#tokens.delete(key);
    this.#pending.delete(key);
  }

  getPending(key: string): Promise<AccessTokenContext> | undefined {
    return this.#pending.get(key);
  }

  setPending(key: string, pending: Promise<AccessTokenContext>): void {
    this.#pending.set(key, pending);
  }

  clearPending(key: string): void {
    this.#pending.delete(key);
  }

  #removeExpired(nowMs: number): void {
    for (const [key, cached] of this.#tokens) {
      if (cached.usableUntilMs <= nowMs) this.#tokens.delete(key);
    }
  }
}

export class OnBehalfOfAuth implements AuthProvider {
  readonly #application: OboApplication;
  readonly #assertion: string;
  readonly #assertionHash: string;
  readonly #upn: string;
  readonly #inboundExpiresAtMs: number;
  readonly #cache: OboTokenCache;
  readonly #now: () => number;
  readonly #results = new Map<TokenResource, AccessTokenContext>();

  constructor(
    application: OboApplication,
    assertion: string,
    upn: string,
    inboundExpiresAt: number,
    cache: OboTokenCache,
    now: () => number = Date.now,
  ) {
    this.#application = application;
    this.#assertion = assertion;
    this.#assertionHash = createHash('sha256').update(assertion).digest('hex');
    this.#upn = upn;
    this.#inboundExpiresAtMs = inboundExpiresAt * 1000;
    this.#cache = cache;
    this.#now = now;
  }

  async getToken(resource: TokenResource): Promise<AccessTokenContext> {
    const key = this.#cacheKey(resource);
    const nowMs = this.#now();
    const cached = this.#cache.get(key, nowMs);
    if (cached !== undefined) {
      this.#results.set(resource, cached);
      return cached;
    }

    const pending = this.#cache.getPending(key);
    if (pending !== undefined) {
      const context = await pending;
      this.#results.set(resource, context);
      return context;
    }

    const acquisition = this.#acquire(resource, key);
    this.#cache.setPending(key, acquisition);
    try {
      const context = await acquisition;
      this.#results.set(resource, context);
      return context;
    } finally {
      this.#cache.clearPending(key);
    }
  }

  getTokenSilently(resource: TokenResource): Promise<AccessTokenContext> {
    return this.getToken(resource);
  }

  invalidate(resource: TokenResource): void {
    this.#results.delete(resource);
    this.#cache.delete(this.#cacheKey(resource));
  }

  async hasUsableToken(resource: TokenResource): Promise<boolean> {
    await this.getToken(resource);
    return true;
  }

  getConnectionStatus(): ConnectionStatus {
    return {
      upn: this.#upn,
      scopes: {
        graph: this.#results.get('graph')?.grantedScopes ?? [],
        mde: this.#results.get('mde')?.grantedScopes ?? [],
      },
    };
  }

  async #acquire(resource: TokenResource, key: string): Promise<AccessTokenContext> {
    let result: AuthenticationResult | null;
    try {
      result = await this.#application.acquireTokenOnBehalfOf({
        oboAssertion: this.#assertion,
        scopes: resource === 'graph' ? [...GRAPH_SCOPES] : [...MDE_TOKEN_SCOPES],
      });
    } catch (error: unknown) {
      throw new OnBehalfOfExchangeError(resource, oboErrorCode(error));
    }
    if (result === null) {
      throw new OnBehalfOfExchangeError(resource, 'no_token_result');
    }

    const context: AccessTokenContext = {
      accessToken: result.accessToken,
      grantedScopes: result.scopes,
      ...(result.expiresOn === null ? {} : { expiresOn: result.expiresOn }),
    };
    const resourceExpiryMs = result.expiresOn?.getTime() ?? this.#inboundExpiresAtMs;
    const usableUntilMs = Math.min(resourceExpiryMs, this.#inboundExpiresAtMs) - EXPIRY_SKEW_MS;
    this.#cache.set(key, context, usableUntilMs, this.#now());
    return context;
  }

  #cacheKey(resource: TokenResource): string {
    return `${this.#assertionHash}:${resource}`;
  }
}

function oboErrorCode(error: unknown): string {
  if (typeof error !== 'object' || error === null) return 'unknown_error';
  const errorCode = (error as { errorCode?: unknown }).errorCode;
  return typeof errorCode === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(errorCode)
    ? errorCode
    : 'unknown_error';
}

function exchangeFailureMessage(resource: TokenResource, errorCode: string): string {
  const resourceName = resource === 'graph' ? 'Microsoft Graph' : 'Defender for Endpoint';
  const permissionApi = resource === 'graph' ? 'Microsoft Graph' : 'WindowsDefenderATP';
  const prefix = `${resourceName} could not be accessed on your behalf (${errorCode}).`;

  if (errorCode === 'invalid_grant') {
    return `${prefix} Ask an administrator to confirm the app registration's delegated ${permissionApi} permissions have admin consent, then retry.`;
  }
  if (errorCode === 'interaction_required' || errorCode === 'consent_required') {
    return `${prefix} Ask an administrator to grant consent for the app registration's delegated ${permissionApi} permissions, then retry.`;
  }
  if (errorCode === 'unauthorized_client') {
    return `${prefix} Ask an administrator to confirm the app registration is authorised for delegated ${permissionApi} on-behalf-of access, then retry.`;
  }
  return `${prefix} Ask an administrator to review the app registration and Entra sign-in logs, then retry.`;
}

export class OnBehalfOfAuthFactory {
  readonly #application: OboApplication;
  readonly #cache = new OboTokenCache();

  constructor(application: OboApplication) {
    this.#application = application;
  }

  create(assertion: string, upn: string, inboundExpiresAt: number): OnBehalfOfAuth {
    return new OnBehalfOfAuth(this.#application, assertion, upn, inboundExpiresAt, this.#cache);
  }
}

export async function createOnBehalfOfAuthFactory(
  config: AppConfig,
): Promise<OnBehalfOfAuthFactory> {
  const application: IConfidentialClientApplication = new ConfidentialClientApplication({
    auth: {
      clientId: config.clientId,
      authority: `https://login.microsoftonline.com/${config.tenantId}`,
      ...(config.clientSecret === undefined ? {} : { clientSecret: config.clientSecret }),
      ...(config.clientCertPath === undefined
        ? {}
        : { clientCertificate: await loadClientCertificate(config.clientCertPath) }),
    },
  });
  return new OnBehalfOfAuthFactory(application);
}

async function loadClientCertificate(path: string): Promise<{
  thumbprintSha256: string;
  privateKey: string;
}> {
  const pem = await readFile(path, 'utf8');
  const certificateMatch = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(pem);
  const privateKeyMatch =
    /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC )?PRIVATE KEY-----/.exec(
      pem,
    );
  if (certificateMatch === null || privateKeyMatch === null) {
    throw new Error('OBO certificate PEM must contain a certificate and private key');
  }
  const certificateDer = Buffer.from(
    certificateMatch[0].replace(/-----[^-]+-----|\s/g, ''),
    'base64',
  );
  return {
    thumbprintSha256: createHash('sha256').update(certificateDer).digest('hex').toUpperCase(),
    privateKey: privateKeyMatch[0],
  };
}
