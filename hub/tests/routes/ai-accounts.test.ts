// AI 帳號：狀態、Claude 授權碼登入、Codex 裝置碼登入、取消、登出、環境變數覆蓋提示、權限與稽核（用假 CLI）。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { eq, like } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GET as accountsGet } from '@/app/api/ai/accounts/route';
import { POST as cancelPost } from '@/app/api/ai/accounts/[provider]/login/cancel/route';
import { POST as completePost } from '@/app/api/ai/accounts/[provider]/login/complete/route';
import { GET as loginGet, POST as loginPost } from '@/app/api/ai/accounts/[provider]/login/route';
import { POST as logoutPost } from '@/app/api/ai/accounts/[provider]/logout/route';
import { auditLog } from '@/drizzle/schema';
import { resetAccountsForTests } from '@/lib/ai/accounts';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const FIX = path.resolve(__dirname, '../fixtures');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asa-ai-accounts-'));
const admin = { authorization: 'Bearer test-admin' };
const ctx = (provider: string) => ({ params: Promise.resolve({ provider }) });
const post = (url: string, body: unknown = {}) => req(url, { method: 'POST', body, headers: admin });
let db: DB;

type Account = { id: string; status: { installed: boolean; loggedIn: boolean; method: string | null; email: string | null; plan: string | null; envOverride: string[] }; login: { state: string } | null };
async function accounts(): Promise<Record<string, Account>> {
  const r = await accountsGet(req('/api/ai/accounts', { headers: admin }));
  expect(r.status).toBe(200);
  const j = (await r.json()) as { providers: Account[] };
  return Object.fromEntries(j.providers.map((p) => [p.id, p]));
}

beforeAll(async () => {
  db = await createTestDb();
});

afterAll(() => {
  resetAccountsForTests();
  fs.rmSync(tmp, { recursive: true, force: true });
});

beforeEach(() => {
  resetAccountsForTests();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLAUDE_BIN = path.join(FIX, 'fake-claude-auth.mjs');
  process.env.ASA_HUB_CODEX_BIN = path.join(FIX, 'fake-codex.mjs');
  process.env.CLAUDE_CONFIG_DIR = path.join(tmp, 'claude');
  process.env.CODEX_HOME = path.join(tmp, 'codex');
  fs.mkdirSync(process.env.CLAUDE_CONFIG_DIR, { recursive: true });
  fs.mkdirSync(process.env.CODEX_HOME, { recursive: true });
  delete process.env.ANTHROPIC_API_KEY;
  resetEnvForTests();
});

describe('ai accounts', () => {
  it('reports status and env overrides; admin only', async () => {
    expect((await accountsGet(req('/api/ai/accounts'))).status).toBe(401);
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    const a = await accounts();
    expect(a.claude.status).toMatchObject({ installed: true, loggedIn: false, envOverride: ['ANTHROPIC_API_KEY'] });
    expect(a.codex.status).toMatchObject({ installed: true, loggedIn: false, envOverride: [] });
    expect(JSON.stringify(a)).not.toContain('sk-test');
    expect((await loginPost(post('/api/ai/accounts/gemini/login'), ctx('gemini'))).status).toBe(404);
  });

  it('claude: shows the authorize URL, rejects a bad code, accepts the right one, and never records it', async () => {
    let r = await (await loginPost(post('/api/ai/accounts/claude/login'), ctx('claude'))).json();
    expect(r.login).toMatchObject({ state: 'waiting_code' });
    expect(r.login.url).toMatch(/^https:\/\/claude\.com\/cai\/oauth\/authorize\?/);
    const bad = await (await completePost(post('/api/ai/accounts/claude/login/complete', { code: 'wrong-code' }), ctx('claude'))).json();
    expect(bad.login).toMatchObject({ state: 'error' });
    expect((await completePost(post('/api/ai/accounts/claude/login/complete', { code: 'x' }), ctx('claude'))).status).toBe(409);

    r = await (await loginPost(post('/api/ai/accounts/claude/login'), ctx('claude'))).json();
    expect(r.login.state).toBe('waiting_code');
    const ok = await (await completePost(post('/api/ai/accounts/claude/login/complete', { code: 'good-code' }), ctx('claude'))).json();
    expect(ok.login.state).toBe('done');
    expect((await accounts()).claude.status).toMatchObject({ loggedIn: true, method: 'claude.ai', email: 'tester@example.com', plan: 'max' });
    const rows = await db.select().from(auditLog).where(like(auditLog.action, 'ai_account.%'));
    expect(rows.map((x) => x.action)).toEqual(expect.arrayContaining(['ai_account.login_started', 'ai_account.login_done']));
    expect(JSON.stringify(rows)).not.toContain('good-code');
    expect(JSON.stringify(rows)).not.toContain('wrong-code');
  });

  it('codex: device code login completes in the background', async () => {
    const r = await (await loginPost(post('/api/ai/accounts/codex/login'), ctx('codex'))).json();
    expect(r.login).toMatchObject({ state: 'waiting_user', url: 'https://auth.openai.com/codex/device', userCode: 'ABCD-EFGHI' });
    fs.writeFileSync(path.join(process.env.CODEX_HOME!, 'approve'), '1');
    let state = '';
    for (let i = 0; i < 50 && state !== 'done'; i++) {
      await new Promise((ok) => setTimeout(ok, 100));
      state = (await (await loginGet(req('/api/ai/accounts/codex/login', { headers: admin }), ctx('codex'))).json()).login.state;
    }
    expect(state).toBe('done');
    expect((await accounts()).codex.status).toMatchObject({ loggedIn: true, method: 'chatgpt' });
    fs.rmSync(path.join(process.env.CODEX_HOME!, 'approve'), { force: true });
  });

  it('cancels a login in progress and logs out', async () => {
    await loginPost(post('/api/ai/accounts/claude/login'), ctx('claude'));
    const c = await (await cancelPost(post('/api/ai/accounts/claude/login/cancel'), ctx('claude'))).json();
    expect(c).toMatchObject({ ok: true, cancelled: true });
    expect((await (await loginGet(req('/api/ai/accounts/claude/login', { headers: admin }), ctx('claude'))).json()).login).toBeNull();

    fs.writeFileSync(path.join(process.env.CLAUDE_CONFIG_DIR!, 'logged'), '1');
    expect((await accounts()).claude.status.loggedIn).toBe(true);
    const out = await logoutPost(post('/api/ai/accounts/claude/logout'), ctx('claude'));
    expect(out.status).toBe(200);
    expect((await out.json()).status.loggedIn).toBe(false);
    expect((await db.select().from(auditLog).where(eq(auditLog.action, 'ai_account.logout'))).length).toBeGreaterThan(0);
    // 沒有 CSRF 標頭的 cookie 寫入擋掉；沒登入 401
    expect((await logoutPost(req('/api/ai/accounts/codex/logout', { method: 'POST', body: {} }), ctx('codex'))).status).toBe(401);
  });
});
