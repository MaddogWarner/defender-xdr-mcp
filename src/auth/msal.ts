import {
  ClientAuthError,
  ClientAuthErrorCodes,
  InteractionRequiredAuthError,
  PublicClientApplication,
  type AccountInfo,
  type AuthenticationResult,
  type DeviceCodeRequest,
  type IPublicClientApplication,
  type SilentFlowRequest,
} from '@azure/msal-node';

import type { AppConfig } from '../config.js';
import { createEncryptedCachePlugin } from './tokenCache.js';

export type TokenResource = 'graph' | 'mde';

export const GRAPH_SCOPES = [
  'https://graph.microsoft.com/ThreatHunting.Read.All',
  'https://graph.microsoft.com/SecurityIncident.Read.All',
  'https://graph.microsoft.com/SecurityAlert.Read.All',
  'https://graph.microsoft.com/User.Read',
] as const;

export const MDE_TOKEN_SCOPES = ['https://api.securitycenter.microsoft.com/.default'] as const;

export const MDE_DELEGATED_PERMISSIONS = [
  'Vulnerability.Read',
  'Machine.Read',
  'Software.Read',
  'SecurityRecommendation.Read',
] as const;

interface TokenApplication {
  getAllAccounts(): Promise<AccountInfo[]>;
  acquireTokenSilent(request: SilentFlowRequest): Promise<AuthenticationResult>;
  acquireTokenByDeviceCode(request: DeviceCodeRequest): Promise<AuthenticationResult | null>;
}

export interface AccessTokenContext {
  accessToken: string;
  account?: AccountInfo;
  grantedScopes: readonly string[];
  expiresOn?: Date;
}

export interface ConnectionStatus {
  upn: string | undefined;
  scopes: Readonly<Record<TokenResource, readonly string[]>>;
}

export interface AuthProvider {
  getToken(resource: TokenResource): Promise<AccessTokenContext>;
  getTokenSilently(resource: TokenResource): Promise<AccessTokenContext>;
  invalidate(resource: TokenResource): void;
  hasUsableToken(resource: TokenResource): Promise<boolean>;
  getConnectionStatus(): ConnectionStatus;
}

export class ResourceInteractionRequiredError extends Error {
  readonly resource: TokenResource;

  constructor(resource: TokenResource) {
    super(
      `${resource === 'graph' ? 'Microsoft Graph' : 'Defender for Endpoint'} requires interactive sign-in. Call get_connection_status to sign in, then retry.`,
    );
    this.name = 'ResourceInteractionRequiredError';
    this.resource = resource;
  }
}

function scopesFor(resource: TokenResource): string[] {
  return resource === 'graph' ? [...GRAPH_SCOPES] : [...MDE_TOKEN_SCOPES];
}

export class DeviceCodeAuth {
  readonly #application: TokenApplication;
  #account: AccountInfo | undefined;
  readonly #results = new Map<TokenResource, AccessTokenContext>();

  constructor(application: TokenApplication) {
    this.#application = application;
  }

  async getToken(resource: TokenResource): Promise<AccessTokenContext> {
    return this.#acquireToken(resource, true);
  }

  async getTokenSilently(resource: TokenResource): Promise<AccessTokenContext> {
    return this.#acquireToken(resource, false);
  }

  invalidate(resource: TokenResource): void {
    this.#results.delete(resource);
  }

  async hasUsableToken(resource: TokenResource): Promise<boolean> {
    try {
      await this.getTokenSilently(resource);
      return true;
    } catch (error: unknown) {
      if (error instanceof ResourceInteractionRequiredError) {
        return false;
      }
      throw error;
    }
  }

  async #acquireToken(
    resource: TokenResource,
    allowInteraction: boolean,
  ): Promise<AccessTokenContext> {
    const cached = this.#results.get(resource);
    if (
      cached?.expiresOn !== undefined &&
      cached.expiresOn.getTime() - Date.now() > 5 * 60 * 1000
    ) {
      return cached;
    }

    const scopes = scopesFor(resource);
    const accounts = await this.#application.getAllAccounts();
    const selectedAccount = accounts.find(
      (candidate) => candidate.homeAccountId === this.#account?.homeAccountId,
    );
    const account =
      selectedAccount ??
      (this.#account === undefined && accounts.length === 1 ? accounts[0] : undefined);

    let result: AuthenticationResult | null = null;
    if (account !== undefined) {
      try {
        result = await this.#application.acquireTokenSilent({ account, scopes });
      } catch (error: unknown) {
        if (!requiresInteraction(error)) {
          throw error;
        }
      }
    }

    if (result === null && !allowInteraction) {
      throw new ResourceInteractionRequiredError(resource);
    }

    if (result === null) {
      result = await this.#application.acquireTokenByDeviceCode({
        scopes,
        ...(account?.username === undefined ? {} : { loginHint: account.username }),
        deviceCodeCallback: ({ message }) => {
          console.error(message);
        },
      });
    }

    if (result?.account === null || result === null) {
      throw new Error(`Microsoft sign-in did not return an account for ${resource}`);
    }

    const token = {
      accessToken: result.accessToken,
      account: result.account,
      grantedScopes: result.scopes,
      ...(result.expiresOn === null ? {} : { expiresOn: result.expiresOn }),
    };
    this.#account = result.account;
    this.#results.set(resource, token);
    return token;
  }

  getConnectionStatus(): ConnectionStatus {
    return {
      upn: this.#account?.username,
      scopes: {
        graph: this.#results.get('graph')?.grantedScopes ?? [],
        mde: this.#results.get('mde')?.grantedScopes ?? [],
      },
    };
  }
}

function requiresInteraction(error: unknown): boolean {
  if (error instanceof InteractionRequiredAuthError) {
    return true;
  }
  if (!(error instanceof ClientAuthError)) {
    return false;
  }
  return new Set<string>([
    ClientAuthErrorCodes.noAccountFound,
    ClientAuthErrorCodes.noAccountInSilentRequest,
    ClientAuthErrorCodes.nullOrEmptyToken,
    ClientAuthErrorCodes.tokenRefreshRequired,
    'no_tokens_found',
  ]).has(error.errorCode);
}

export async function createDeviceCodeAuth(config: AppConfig): Promise<DeviceCodeAuth> {
  const cachePlugin = await createEncryptedCachePlugin(config.clientId);
  const application: IPublicClientApplication = new PublicClientApplication({
    auth: {
      clientId: config.clientId,
      authority: `https://login.microsoftonline.com/${config.tenantId}`,
    },
    cache: { cachePlugin },
  });

  return new DeviceCodeAuth(application);
}
