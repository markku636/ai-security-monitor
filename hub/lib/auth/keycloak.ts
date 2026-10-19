import { createHash } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { keycloakLoginEnabled, readEnv } from '@/lib/env';
import { hubPublicUrl } from '@/lib/install';
import { randomToken, safeEqual } from './crypto';

export const KEYCLOAK_STATE_COOKIE = 'asa_keycloak_state';
export const KEYCLOAK_NONCE_COOKIE = 'asa_keycloak_nonce';
export const KEYCLOAK_VERIFIER_COOKIE = 'asa_keycloak_verifier';
export const KEYCLOAK_COOKIE_MAX_AGE = 10 * 60;
export const KEYCLOAK_CALLBACK_PATH = '/api/auth/keycloak/callback';

export interface KeycloakLoginConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  allowedEmails: string[];
  only: boolean;
  idpHint: string;
}

interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

interface TokenResponse {
  id_token?: string;
  error?: string;
  error_description?: string;
}

function csv(name: string): string[] {
  return readEnv(name)
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
}

function flag(name: string): boolean {
  return ['1', 'true', 'yes', 'on'].includes(readEnv(name).toLowerCase());
}

export function keycloakLoginConfig(): KeycloakLoginConfig {
  return {
    enabled: keycloakLoginEnabled(),
    issuer: readEnv('ASA_HUB_KEYCLOAK_ISSUER').replace(/\/+$/, ''),
    clientId: readEnv('ASA_HUB_KEYCLOAK_CLIENT_ID'),
    clientSecret: readEnv('ASA_HUB_KEYCLOAK_CLIENT_SECRET'),
    allowedEmails: csv('ASA_HUB_KEYCLOAK_ALLOWED_EMAILS'),
    only: flag('ASA_HUB_KEYCLOAK_ONLY'),
    idpHint: readEnv('ASA_HUB_KEYCLOAK_IDP_HINT'),
  };
}

const g = globalThis as unknown as { __asaKeycloakDiscovery?: { issuer: string; value: OidcDiscovery; expiresAt: number } };

export async function discoverKeycloak(cfg: KeycloakLoginConfig, fetchImpl: typeof fetch = fetch): Promise<OidcDiscovery> {
  const issuerUrl = new URL(cfg.issuer);
  if (issuerUrl.protocol !== 'https:') throw new Error('keycloak_insecure_issuer');
  if (g.__asaKeycloakDiscovery?.issuer === cfg.issuer && g.__asaKeycloakDiscovery.expiresAt > Date.now()) {
    return g.__asaKeycloakDiscovery.value;
  }
  const response = await fetchImpl(`${cfg.issuer}/.well-known/openid-configuration`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(10_000),
    cache: 'no-store',
  });
  if (!response.ok) throw new Error(`keycloak_discovery_${response.status}`);
  const value = (await response.json()) as Partial<OidcDiscovery>;
  if (
    value.issuer !== cfg.issuer ||
    typeof value.authorization_endpoint !== 'string' ||
    typeof value.token_endpoint !== 'string' ||
    typeof value.jwks_uri !== 'string' ||
    !value.authorization_endpoint.startsWith('https://') ||
    !value.token_endpoint.startsWith('https://') ||
    !value.jwks_uri.startsWith('https://')
  ) {
    throw new Error('keycloak_bad_discovery');
  }
  const result = value as OidcDiscovery;
  g.__asaKeycloakDiscovery = { issuer: cfg.issuer, value: result, expiresAt: Date.now() + 10 * 60_000 };
  return result;
}

export function keycloakRedirectUri(headers: Headers, reqUrl?: string): string {
  const base = hubPublicUrl(headers, reqUrl);
  if (!base) throw new Error('keycloak_public_url_missing');
  return `${base}${KEYCLOAK_CALLBACK_PATH}`;
}

export function createKeycloakRequest(): { state: string; nonce: string; verifier: string; challenge: string } {
  const state = randomToken();
  const nonce = randomToken();
  const verifier = randomToken();
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { state, nonce, verifier, challenge };
}

export function keycloakTransientCookie(name: string, value: string, secure: boolean, maxAge = KEYCLOAK_COOKIE_MAX_AGE): string {
  return [`${name}=${encodeURIComponent(value)}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${maxAge}`, secure ? 'Secure' : '']
    .filter(Boolean)
    .join('; ');
}

export function buildKeycloakAuthorizationUrl(
  discovery: OidcDiscovery,
  cfg: KeycloakLoginConfig,
  redirectUri: string,
  request: ReturnType<typeof createKeycloakRequest>,
): string {
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', request.state);
  url.searchParams.set('nonce', request.nonce);
  url.searchParams.set('code_challenge', request.challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (cfg.idpHint) url.searchParams.set('kc_idp_hint', cfg.idpHint);
  return url.toString();
}

export async function exchangeKeycloakCode(
  discovery: OidcDiscovery,
  cfg: KeycloakLoginConfig,
  input: { code: string; verifier: string; redirectUri: string },
  fetchImpl: typeof fetch = fetch,
): Promise<TokenResponse> {
  const response = await fetchImpl(discovery.token_endpoint, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: input.redirectUri,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code_verifier: input.verifier,
    }),
    signal: AbortSignal.timeout(10_000),
    cache: 'no-store',
  });
  const result = (await response.json()) as TokenResponse;
  if (!response.ok || !result.id_token) throw new Error(result.error || `keycloak_token_${response.status}`);
  return result;
}

export async function verifyKeycloakIdToken(
  idToken: string,
  discovery: OidcDiscovery,
  cfg: KeycloakLoginConfig,
  nonce: string,
): Promise<JWTPayload> {
  const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri), { timeoutDuration: 10_000, cooldownDuration: 30_000 });
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: cfg.issuer,
    audience: cfg.clientId,
    algorithms: ['RS256'],
  });
  if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, nonce)) throw new Error('keycloak_nonce_mismatch');
  if (!payload.sub) throw new Error('keycloak_subject_missing');
  return payload;
}

export function keycloakClaimAllowed(payload: JWTPayload, cfg = keycloakLoginConfig()): boolean {
  const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : '';
  return payload.email_verified === true && cfg.allowedEmails.includes(email);
}

export function keycloakActor(payload: JWTPayload): string {
  const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : String(payload.sub);
  return `keycloak:${email.slice(0, 200)}`;
}

export function resetKeycloakForTests(): void {
  g.__asaKeycloakDiscovery = undefined;
}
