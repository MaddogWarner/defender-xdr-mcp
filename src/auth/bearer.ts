import { createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWTVerifyGetKey } from 'jose';
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';

import type { AppConfig } from '../config.js';

const REQUIRED_SCOPE = 'access_as_user';

export class EntraTokenVerifier implements OAuthTokenVerifier {
  readonly #tenantId: string;
  readonly #clientId: string;
  readonly #issuer: string;
  readonly #getKey: JWTVerifyGetKey;
  readonly #reportVerificationFailure: (message: string) => void;

  constructor(
    config: Pick<AppConfig, 'tenantId' | 'clientId'>,
    getKey?: JWTVerifyGetKey,
    reportVerificationFailure: (message: string) => void = (message) => console.error(message),
  ) {
    this.#tenantId = config.tenantId;
    this.#clientId = config.clientId;
    this.#issuer = `https://login.microsoftonline.com/${config.tenantId}/v2.0`;
    this.#getKey =
      getKey ??
      createRemoteJWKSet(
        new URL(`https://login.microsoftonline.com/${config.tenantId}/discovery/v2.0/keys`),
      );
    this.#reportVerificationFailure = reportVerificationFailure;
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const { payload } = await jwtVerify(token, this.#getKey, {
        issuer: this.#issuer,
        audience: [this.#clientId, `api://${this.#clientId}`],
        algorithms: ['RS256'],
      });
      if (payload.tid !== this.#tenantId) {
        throw new joseErrors.JWTClaimValidationFailed(
          'unexpected tenant claim',
          payload,
          'tid',
          'check_failed',
        );
      }
      if (typeof payload.exp !== 'number') {
        throw new joseErrors.JWTClaimValidationFailed(
          'missing expiration claim',
          payload,
          'exp',
          'missing',
        );
      }
      const scopes =
        typeof payload.scp === 'string' ? payload.scp.split(/\s+/).filter(Boolean) : [];
      if (!scopes.includes(REQUIRED_SCOPE)) {
        throw new joseErrors.JWTClaimValidationFailed(
          'required scope is missing',
          payload,
          'scp',
          'check_failed',
        );
      }
      const upn = bearerUpn(payload);
      if (upn === undefined) {
        throw new joseErrors.JWTClaimValidationFailed(
          'user principal name is missing',
          payload,
          'preferred_username',
          'missing',
        );
      }
      return {
        token,
        clientId: this.#clientId,
        scopes,
        expiresAt: payload.exp,
        extra: {
          upn,
          ...(typeof payload.oid === 'string' ? { oid: payload.oid } : {}),
          tid: this.#tenantId,
        },
      };
    } catch (error: unknown) {
      if (error instanceof OAuthError) {
        throw error;
      }
      if (isJwksInfrastructureFailure(error)) {
        this.#reportVerificationFailure(
          `Entra JWKS verification is unavailable (${verificationFailureCode(error)})`,
        );
        throw new OAuthError(
          OAuthErrorCode.ServerError,
          'The server cannot verify bearer tokens at present',
        );
      }
      throw new OAuthError(OAuthErrorCode.InvalidToken, 'The bearer token is invalid or expired');
    }
  }
}

function isJwksInfrastructureFailure(error: unknown): boolean {
  if (error instanceof TypeError || error instanceof joseErrors.JWKSTimeout) {
    return true;
  }
  return (
    error instanceof joseErrors.JOSEError &&
    (error.code === 'ERR_JOSE_GENERIC' || error.code === 'ERR_JWKS_INVALID')
  );
}

function verificationFailureCode(error: unknown): string {
  if (error instanceof joseErrors.JOSEError) return error.code;
  return error instanceof Error ? error.name : 'unknown_error';
}

export function authInfoUpn(authInfo: AuthInfo): string {
  const upn = authInfo.extra?.upn;
  if (typeof upn !== 'string' || upn.length === 0) {
    throw new OAuthError(OAuthErrorCode.InvalidToken, 'The bearer token has no user identity');
  }
  return upn;
}

function bearerUpn(payload: Record<string, unknown>): string | undefined {
  const preferredUsername = payload.preferred_username;
  if (typeof preferredUsername === 'string' && preferredUsername.length > 0) {
    return preferredUsername;
  }
  const upn = payload.upn;
  return typeof upn === 'string' && upn.length > 0 ? upn : undefined;
}
