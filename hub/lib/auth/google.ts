import { createHash } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { googleLoginEnabled, readEnv } from '@/lib/env';
import { hubPublicUrl } from '@/lib/install';
import { randomToken, safeEqual } from './crypto';

export const GOOGLE_STATE_COOKIE = 'asa_google_state';
export const GOOGLE_NONCE_COOKIE = 'asa_google_nonce';
export const GOOGLE_VERIFIER_COOKIE = 'asa_google_verifier';
export const GOOGLE_COOKIE_MAX_AGE = 10 * 60;
export const GOOGLE_CALLBACK_PATH = '/api/auth/google/callback';

export interface GoogleLoginConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  allowedEmails: string[];
  only: boolean;
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

export function googleLoginConfig(): GoogleLoginConfig {
  return {
    enabled: googleLoginEnabled(),
    issuer: 'https://accounts.google.com',
    clientId: readEnv('ASA_HUB_GOOGLE_CLIENT_ID'),
    clientSecret: readEnv('ASA_HUB_GOOGLE_CLIENT_SECRET'),
    allowedEmails: csv('ASA_HUB_GOOGLE_ALLOWED_EMAILS'),
    only: flag('ASA_HUB_GOOGLE_ONLY'),
  };
}

const g = globalThis as unknown as { __asaGoogleDiscovery?: { issuer: string; value: OidcDiscovery; expiresAt: number } };

export async function discoverGoogle(cfg: GoogleLoginConfig, fetchImpl: typeof fetch = fetch): Promise<OidcDiscovery> {
  const issuerUrl = new URL(cfg.issuer);
  if (issuerUrl.protocol !== 'https:') throw new Error('google_insecure_issuer');
  if (g.__asaGoogleDiscovery?.issuer === cfg.issuer && g.__asaGoogleDiscovery.expiresAt > Date.now()) {
    return g.__asaGoogleDiscovery.value;
  }
  const response = await fetchImpl(`${cfg.issuer}/.well-known/openid-configuration`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(10_000),
    cache: 'no-store',
  });
  if (!response.ok) throw new Error(`google_discovery_${response.status}`);
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
    throw new Error('google_bad_discovery');
  }
  const result = value as OidcDiscovery;
  g.__asaGoogleDiscovery = { issuer: cfg.issuer, value: result, expiresAt: Date.now() + 10 * 60_000 };
  return result;
}

export function googleRedirectUri(headers: Headers, reqUrl?: string): string {
  const base = hubPublicUrl(headers, reqUrl);
  if (!base) throw new Error('google_public_url_missing');
  return `${base}${GOOGLE_CALLBACK_PATH}`;
}

export function createGoogleRequest(): { state: string; nonce: string; verifier: string; challenge: string } {
  const state = randomToken();
  const nonce = randomToken();
  const verifier = randomToken();
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { state, nonce, verifier, challenge };
}

export function googleTransientCookie(name: string, value: string, secure: boolean, maxAge = GOOGLE_COOKIE_MAX_AGE): string {
  return [`${name}=${encodeURIComponent(value)}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${maxAge}`, secure ? 'Secure' : '']
    .filter(Boolean)
    .join('; ');
}

export function buildGoogleAuthorizationUrl(
  discovery: OidcDiscovery,
  cfg: GoogleLoginConfig,
  redirectUri: string,
  request: ReturnType<typeof createGoogleRequest>,
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
  url.searchParams.set('prompt', 'select_account');
  return url.toString();
}

export async function exchangeGoogleCode(
  discovery: OidcDiscovery,
  cfg: GoogleLoginConfig,
  input: { code: string; verifier: string; redirectUri: string },
  fetchImpl: typeof fetch = fetch,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: cfg.clientId,
    code_verifier: input.verifier,
  });
  // Confidential clients use a secret; public PKCE clients intentionally do not.
  if (cfg.clientSecret) body.set('client_secret', cfg.clientSecret);
  const response = await fetchImpl(discovery.token_endpoint, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body,
    signal: AbortSignal.timeout(10_000),
    cache: 'no-store',
  });
  const result = (await response.json()) as TokenResponse;
  if (!response.ok || !result.id_token) throw new Error(result.error || `google_token_${response.status}`);
  return result;
}

export async function verifyGoogleIdToken(
  idToken: string,
  discovery: OidcDiscovery,
  cfg: GoogleLoginConfig,
  nonce: string,
): Promise<JWTPayload> {
  const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri), { timeoutDuration: 10_000, cooldownDuration: 30_000 });
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: ['https://accounts.google.com', 'accounts.google.com'],
    audience: cfg.clientId,
    algorithms: ['RS256'],
    requiredClaims: ['exp', 'sub', 'nonce'],
  });
  if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, nonce)) throw new Error('google_nonce_mismatch');
  if (payload.azp !== undefined && payload.azp !== cfg.clientId) throw new Error('google_authorized_party_mismatch');
  if (!payload.sub) throw new Error('google_subject_missing');
  return payload;
}

export function googleClaimAllowed(payload: JWTPayload, cfg = googleLoginConfig()): boolean {
  const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : '';
  return payload.email_verified === true && cfg.allowedEmails.includes(email);
}

export function googleActor(payload: JWTPayload): string {
  const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : String(payload.sub);
  return `google:${email.slice(0, 200)}`;
}

export function resetGoogleForTests(): void {
  g.__asaGoogleDiscovery = undefined;
}
