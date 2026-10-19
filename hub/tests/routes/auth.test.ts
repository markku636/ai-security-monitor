import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GET as health } from '@/app/api/health/route';
import { POST as login } from '@/app/api/auth/login/route';
import { POST as logout } from '@/app/api/auth/logout/route';
import { GET as me } from '@/app/api/auth/me/route';
import { POST as prefs } from '@/app/api/prefs/route';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { loadEnv, resetEnvForTests } from '@/lib/env';
import { createTestDb } from '../helpers/db';
import { cookieFrom, req } from '../helpers/req';
import { googleClaimAllowed, googleLoginConfig, resetGoogleForTests } from '@/lib/auth/google';

function setEnv(vars: Record<string, string | undefined>) {
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  resetEnvForTests();
}

beforeAll(async () => {
  await createTestDb();
});

beforeEach(() => {
  resetRateLimitsForTests();
  resetGoogleForTests();
  setEnv({
    ASA_HUB_ADMIN_SECRET: 'test-admin',
    ASA_HUB_CLIENT_SECRETS: 'client-a,client-b',
    ASA_HUB_PUBLIC_DASHBOARD: undefined,
    ASA_HUB_GOOGLE_CLIENT_ID: undefined,
    ASA_HUB_GOOGLE_CLIENT_SECRET: undefined,
    ASA_HUB_GOOGLE_ALLOWED_EMAILS: undefined,
    ASA_HUB_GOOGLE_ONLY: undefined,
  });
});

describe('health', () => {
  it('reports the database as ok', async () => {
    const r = await health();
    expect(r.status).toBe(200);
    const b = await r.json();
    expect(b.ok).toBe(true);
    expect(b.db).toBe('ok');
    expect(b.open_mode).toBe(false);
  });
});

describe('login / me / logout', () => {
  it('rejects a wrong key and accepts the admin key', async () => {
    const bad = await login(req('/api/auth/login', { method: 'POST', body: { key: 'nope' } }));
    expect(bad.status).toBe(401);
    const ok = await login(req('/api/auth/login', { method: 'POST', body: { key: 'test-admin' } }));
    expect(ok.status).toBe(200);
    const sc = ok.headers.get('set-cookie')!;
    expect(sc).toContain('HttpOnly');
    expect(sc).toContain('SameSite=Strict');
    const cookie = cookieFrom(ok, 'asa_admin')!;

    const who = await (await me(req('/api/auth/me', { cookie }))).json();
    expect(who).toMatchObject({ role: 'admin', via: 'session' });

    const out = await logout(req('/api/auth/logout', { method: 'POST', body: {}, cookie }));
    expect(out.status).toBe(200);
    const after = await (await me(req('/api/auth/me', { cookie }))).json();
    expect(after.role).toBe('none');
  });

  it('refuses cross-site writes', async () => {
    const r = await login(req('/api/auth/login', { method: 'POST', body: { key: 'test-admin' }, sameSite: false }));
    expect(r.status).toBe(403);
  });

  it('rate-limits after five failures per minute', async () => {
    for (let i = 0; i < 5; i++) {
      await login(req('/api/auth/login', { method: 'POST', body: { key: `bad-${i}` } }));
    }
    const r = await login(req('/api/auth/login', { method: 'POST', body: { key: 'test-admin' } }));
    expect(r.status).toBe(429);
    expect(r.headers.get('retry-after')).toBe('60');
  });

  it('identifies bearer keys', async () => {
    const admin = await (await me(req('/api/auth/me', { headers: { authorization: 'Bearer test-admin' } }))).json();
    expect(admin).toMatchObject({ role: 'admin', via: 'bearer' });
    const client = await (await me(req('/api/auth/me', { headers: { authorization: 'Bearer client-b' } }))).json();
    expect(client).toMatchObject({ role: 'client', via: 'bearer' });
    const none = await (await me(req('/api/auth/me', { headers: { authorization: 'Bearer x' } }))).json();
    expect(none.role).toBe('none');
  });

  it('a rotated admin secret invalidates existing sessions', async () => {
    const ok = await login(req('/api/auth/login', { method: 'POST', body: { key: 'test-admin' } }));
    const cookie = cookieFrom(ok, 'asa_admin')!;
    setEnv({ ASA_HUB_ADMIN_SECRET: 'rotated', ASA_HUB_CLIENT_SECRETS: undefined });
    const who = await (await me(req('/api/auth/me', { cookie }))).json();
    expect(who.role).toBe('none');
  });

  it('open mode makes everyone admin', async () => {
    setEnv({ ASA_HUB_ADMIN_SECRET: undefined, ASA_HUB_CLIENT_SECRETS: undefined });
    const who = await (await me(req('/api/auth/me'))).json();
    expect(who).toMatchObject({ role: 'admin', via: 'open', open_mode: true });
  });

  it('open mode only trusts a loopback Host (DNS rebinding, LAN)', async () => {
    setEnv({ ASA_HUB_ADMIN_SECRET: undefined, ASA_HUB_CLIENT_SECRETS: undefined, ASA_HUB_ALLOW_OPEN_MODE: undefined });
    for (const host of ['evil.example:3000', '192.168.1.20:3000']) {
      const who = await (await me(req('/api/auth/me', { headers: { host } }))).json();
      expect(who.role).toBe('none');
      expect((await login(req('/api/auth/login', { method: 'POST', body: { key: 'x' }, headers: { host, origin: `http://${host}` } }))).status).toBe(403);
    }
    expect((await (await me(req('/api/auth/me', { headers: { host: '[::1]:3000' } }))).json()).role).toBe('admin');
    // Docker 明確允許（只在 docker 網路內用）
    setEnv({ ASA_HUB_ALLOW_OPEN_MODE: '1' });
    expect((await (await me(req('/api/auth/me', { headers: { host: 'hub:3000' } }))).json()).role).toBe('admin');
    setEnv({ ASA_HUB_ALLOW_OPEN_MODE: undefined });
  });

  it('stops guessing the admin key over Bearer after 100 failures', async () => {
    for (let i = 0; i < 100; i++) {
      expect((await (await me(req('/api/auth/me', { headers: { authorization: `Bearer guess-${i}` } }))).json()).role).toBe('none');
    }
    // 之後連正確的金鑰也先擋（不然猜中就進得來）
    expect((await (await me(req('/api/auth/me', { headers: { authorization: 'Bearer test-admin' } }))).json()).role).toBe('none');
    resetRateLimitsForTests();
    expect((await (await me(req('/api/auth/me', { headers: { authorization: 'Bearer test-admin' } }))).json()).role).toBe('admin');
  });

  it('counts a login attempt before checking it (parallel requests cannot bypass the limit)', async () => {
    const tries = await Promise.all(Array.from({ length: 12 }, () => login(req('/api/auth/login', { method: 'POST', body: { key: 'wrong' } }))));
    expect(tries.filter((r) => r.status === 401).length).toBeLessThanOrEqual(5);
    expect(tries.filter((r) => r.status === 429).length).toBeGreaterThanOrEqual(7);
  });

  it('public dashboard gives read-only viewers', async () => {
    setEnv({ ASA_HUB_PUBLIC_DASHBOARD: '1' });
    const who = await (await me(req('/api/auth/me'))).json();
    expect(who.role).toBe('viewer');
  });

  it('can make Google the only web login and allow exactly one verified email', async () => {
    setEnv({
      ASA_HUB_GOOGLE_CLIENT_ID: 'test.apps.googleusercontent.com',
      ASA_HUB_GOOGLE_ALLOWED_EMAILS: 'a4756830@gmail.com',
    });
    expect(googleLoginConfig().enabled).toBe(false);

    setEnv({
      ASA_HUB_GOOGLE_CLIENT_ID: 'test.apps.googleusercontent.com',
      ASA_HUB_GOOGLE_CLIENT_SECRET: 'test-client-secret',
      ASA_HUB_GOOGLE_ALLOWED_EMAILS: 'a4756830@gmail.com',
      ASA_HUB_GOOGLE_ONLY: '1',
    });
    const cfg = googleLoginConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.only).toBe(true);
    expect(googleClaimAllowed({ sub: '1', email: 'a4756830@gmail.com', email_verified: true }, cfg)).toBe(true);
    expect(googleClaimAllowed({ sub: '2', email: 'someone@example.com', email_verified: true }, cfg)).toBe(false);
    expect(googleClaimAllowed({ sub: '3', email: 'a4756830@gmail.com', email_verified: false }, cfg)).toBe(false);
    const keyLogin = await login(req('/api/auth/login', { method: 'POST', body: { key: 'test-admin' } }));
    expect(keyLogin.status).toBe(403);
    expect(await keyLogin.json()).toMatchObject({ error: 'google_login_only' });
  });
});

describe('env validation', () => {
  it('refuses a client key equal to the admin key', () => {
    setEnv({ ASA_HUB_ADMIN_SECRET: 'same', ASA_HUB_CLIENT_SECRETS: 'same' });
    expect(() => loadEnv()).toThrow();
    setEnv({ ASA_HUB_ADMIN_SECRET: undefined, ASA_HUB_CLIENT_SECRETS: 'x' });
    expect(() => loadEnv()).toThrow();
  });
});

describe('prefs', () => {
  it('sets language and theme cookies', async () => {
    const r = await prefs(req('/api/prefs', { method: 'POST', body: { lang: 'en', theme: 'dark' } }));
    expect(r.status).toBe(200);
    const all = r.headers.getSetCookie();
    expect(all.some((c) => c.startsWith('asa_lang=en'))).toBe(true);
    expect(all.some((c) => c.startsWith('asa_theme=dark'))).toBe(true);
    const bad = await prefs(req('/api/prefs', { method: 'POST', body: { lang: 'fr' } }));
    expect(bad.status).toBe(400);
  });
});
