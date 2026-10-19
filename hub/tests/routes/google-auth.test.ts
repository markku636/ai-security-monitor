import { beforeAll, beforeEach, afterEach, expect, it, vi } from 'vitest';
import { GET as start } from '@/app/api/auth/google/login/route';
import { GET as callback } from '@/app/api/auth/google/callback/route';
import { POST as login } from '@/app/api/auth/login/route';
import { googleClaimAllowed, googleLoginConfig, resetGoogleForTests } from '@/lib/auth/google';
import { isOpenMode, resetEnvForTests } from '@/lib/env';
import { secretFingerprint } from '@/lib/auth/sessions';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

beforeAll(async () => { await createTestDb(); });
beforeEach(() => {
  vi.stubEnv('ASA_HUB_ADMIN_SECRET', 'admin-test');
  vi.stubEnv('ASA_HUB_CLIENT_SECRETS', '');
  vi.stubEnv('ASA_HUB_GOOGLE_CLIENT_ID', 'google-test-client');
  vi.stubEnv('ASA_HUB_GOOGLE_CLIENT_SECRET', 'google-test-secret');
  vi.stubEnv('ASA_HUB_GOOGLE_ALLOWED_EMAILS', 'owner@example.com');
  vi.stubEnv('ASA_HUB_GOOGLE_ONLY', '1');
  vi.stubEnv('ASA_HUB_PUBLIC_URL', 'https://security.example.com');
  resetEnvForTests();
  resetGoogleForTests();
});
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); resetEnvForTests(); });

it('redirects directly to Google with PKCE, state, nonce, and secure cookies', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({
    issuer: 'https://accounts.google.com',
    authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_endpoint: 'https://oauth2.googleapis.com/token',
    jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
  })));
  const response = await start(new Request('https://security.example.com/api/auth/google/login'));
  expect(response.status).toBe(302);
  const url = new URL(response.headers.get('location')!);
  expect(url.hostname).toBe('accounts.google.com');
  expect(url.searchParams.get('redirect_uri')).toBe('https://security.example.com/api/auth/google/callback');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('state')).toBeTruthy();
  expect(url.searchParams.get('nonce')).toBeTruthy();
  expect(url.searchParams.has('client_secret')).toBe(false);
  const cookies = response.headers.getSetCookie();
  expect(cookies).toHaveLength(3);
  for (const cookie of cookies) { expect(cookie).toContain('HttpOnly'); expect(cookie).toContain('Secure'); }
});

it('rejects mismatched callback state before exchanging any code', async () => {
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  const response = await callback(req('/api/auth/google/callback?code=code&state=bad', {
    cookie: 'asa_google_state=good; asa_google_nonce=nonce; asa_google_verifier=verifier',
  }));
  expect(response.headers.get('location')).toBe('/login?error=google_state');
  expect(fetcher).not.toHaveBeenCalled();
  expect(response.headers.getSetCookie().every((c) => c.includes('Max-Age=0'))).toBe(true);
});

it('requires an explicitly allowed and verified email', () => {
  expect(googleClaimAllowed({ sub: '1', email: 'OWNER@example.com', email_verified: true })).toBe(true);
  expect(googleClaimAllowed({ sub: '1', email: 'owner@example.com', email_verified: false })).toBe(false);
  expect(googleClaimAllowed({ sub: '2', email: 'stranger@example.com', email_verified: true })).toBe(false);
});

it('blocks admin form login in Google-only mode', async () => {
  const response = await login(req('/api/auth/login', { method: 'POST', body: { key: 'admin-test' } }));
  expect(response.status).toBe(403);
  expect(await response.json()).toEqual({ error: 'google_login_only' });
});

it('fails closed for partial Google configuration without an admin key', async () => {
  vi.stubEnv('ASA_HUB_ADMIN_SECRET', '');
  vi.stubEnv('ASA_HUB_GOOGLE_ALLOWED_EMAILS', ', ,');
  vi.stubEnv('ASA_HUB_GOOGLE_ONLY', '');
  resetEnvForTests();
  expect(googleLoginConfig().enabled).toBe(false);
  expect(isOpenMode()).toBe(false);
  const response = await login(req('/api/auth/login', { method: 'POST', body: { key: ' ' } }));
  expect(response.status).toBe(401);
});

it('invalidates sessions when the Google allowlist changes', () => {
  const original = secretFingerprint();
  vi.stubEnv('ASA_HUB_GOOGLE_ALLOWED_EMAILS', 'other@example.com');
  expect(secretFingerprint()).not.toBe(original);
});
