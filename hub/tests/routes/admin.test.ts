import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GET as installPs1 } from '@/app/install.ps1/route';
import { GET as installSh } from '@/app/install.sh/route';
import { POST as mcpPost } from '@/app/api/mcp/route';
import { GET as auditGet } from '@/app/api/v1/admin/audit/route';
import { DELETE as enrollDelete } from '@/app/api/v1/admin/enroll-keys/[id]/route';
import { GET as enrollGet, POST as enrollPost } from '@/app/api/v1/admin/enroll-keys/route';
import { DELETE as tokenDelete } from '@/app/api/v1/admin/tokens/[id]/route';
import { GET as tokensGet, POST as tokensPost } from '@/app/api/v1/admin/tokens/route';
import { GET as actionsGet, POST as actionsPost } from '@/app/api/v1/actions/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { GET as exportGet } from '@/app/api/v1/export/[file]/route';
import { agents, apiTokens } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { resetTokenTouchForTests } from '@/lib/auth/tokens';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { safeHubUrl } from '@/lib/install';
import { csvCell, toCsv } from '@/lib/queries/admin';
import { newer } from '@/lib/update';
import { createTestDb } from '../helpers/db';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));

const req = (url: string, init: RequestInit & { token?: string } = {}) =>
  new Request(`http://localhost:3000${url}`, {
    ...init,
    headers: { 'content-type': 'application/json', host: 'localhost:3000', ...(init.token ? { authorization: `Bearer ${init.token}` } : {}), ...(init.headers ?? {}) },
  });
const admin = (url: string, init: RequestInit = {}) => req(url, { ...init, token: 'test-admin' });
const params = <T extends Record<string, string>>(p: T) => ({ params: Promise.resolve(p) });

async function makeToken(scopes: string[], name = 't') {
  const r = await tokensPost(admin('/api/v1/admin/tokens', { method: 'POST', body: JSON.stringify({ name, scopes, expires_days: 30 }) }));
  expect(r.status).toBe(201);
  return (await r.json()) as { token: string; item: { id: string; hint: string } };
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
});

beforeEach(() => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
  delete process.env.ASA_HUB_MCP_TOKEN;
  delete process.env.ASA_HUB_PUBLIC_URL;
  resetEnvForTests();
  resetThrottleForTests();
  resetRateLimitsForTests();
  resetTokenTouchForTests();
});

describe('API tokens', () => {
  it('creates scoped read-only tokens that are shown once', async () => {
    const { token, item } = await makeToken(['read']);
    expect(token).toMatch(/^asa_[0-9a-f]{8}_[0-9a-f]{40}$/);
    expect(item.hint).toBe(`asa_${item.id}_…`);
    const list = await (await tokensGet(admin('/api/v1/admin/tokens'))).json();
    expect(JSON.stringify(list)).not.toContain(token);
    // 讀取可以、寫入與管理不行
    expect((await actionsGet(req('/api/v1/actions', { token }))).status).toBe(200);
    expect((await actionsPost(req('/api/v1/actions', { token, method: 'POST', body: '{}' }))).status).toBe(401);
    expect((await tokensGet(req('/api/v1/admin/tokens', { token }))).status).toBe(403);
    expect((await auditGet(req('/api/v1/admin/audit', { token }))).status).toBe(403);
    expect((await exportGet(req('/api/v1/export/agents.csv', { token }), params({ file: 'agents.csv' }))).status).toBe(403);
    // 格式對但不存在、或被竄改
    expect((await actionsGet(req('/api/v1/actions', { token: token.slice(0, -1) + (token.endsWith('0') ? '1' : '0') }))).status).toBe(401);
    expect((await actionsGet(req('/api/v1/actions', { token: 'asa_00000000_' + '0'.repeat(40) }))).status).toBe(401);
  });

  it('enforces export and mcp scopes, expiry and revocation', async () => {
    const exp = await makeToken(['export']);
    const csv = await exportGet(req('/api/v1/export/agents.csv', { token: exp.token }), params({ file: 'agents.csv' }));
    expect(csv.status).toBe(200);
    expect(csv.headers.get('content-type')).toContain('text/csv');
    const bytes = new Uint8Array(await csv.arrayBuffer());
    expect([...bytes.slice(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    expect(new TextDecoder().decode(bytes).startsWith('hostname,status,os')).toBe(true);
    expect((await exportGet(req('/api/v1/export/nope.csv', { token: exp.token }), params({ file: 'nope.csv' }))).status).toBe(404);
    expect((await exportGet(req('/api/v1/export/audit.csv', { token: exp.token }), params({ file: 'audit.csv' }))).status).toBe(403);

    const mcpCall = (token: string) =>
      mcpPost(req('/api/mcp', { token, method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) }));
    expect((await mcpCall(exp.token)).status).toBe(401);
    const m = await makeToken(['mcp']);
    expect((await mcpCall(m.token)).status).toBe(200);

    // 過期
    await db.update(apiTokens).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(apiTokens.id, m.item.id));
    expect((await mcpCall(m.token)).status).toBe(401);
    // 撤銷
    expect((await tokenDelete(admin(`/api/v1/admin/tokens/${exp.item.id}`, { method: 'DELETE' }), params({ id: exp.item.id }))).status).toBe(200);
    expect((await tokenDelete(admin(`/api/v1/admin/tokens/${exp.item.id}`, { method: 'DELETE' }), params({ id: exp.item.id }))).status).toBe(404);
    expect((await exportGet(req('/api/v1/export/agents.csv', { token: exp.token }), params({ file: 'agents.csv' }))).status).toBe(401);
    const list = (await (await tokensGet(admin('/api/v1/admin/tokens'))).json()).items as { id: string; status: string }[];
    expect(list.find((x) => x.id === exp.item.id)?.status).toBe('revoked');
    expect(list.find((x) => x.id === m.item.id)?.status).toBe('expired');
    // 稽核
    const audit = (await (await auditGet(admin('/api/v1/admin/audit?action=token.'))).json()).items as { action: string }[];
    expect(audit.map((a) => a.action)).toContain('token.revoked');
  });

  it('rejects bad input and cookie writes without the CSRF header', async () => {
    expect((await tokensPost(admin('/api/v1/admin/tokens', { method: 'POST', body: JSON.stringify({ name: 'x', scopes: ['admin'] }) }))).status).toBe(400);
    expect((await tokensPost(admin('/api/v1/admin/tokens', { method: 'POST', body: JSON.stringify({ name: '', scopes: ['read'] }) }))).status).toBe(400);
    expect((await tokensPost(req('/api/v1/admin/tokens', { method: 'POST', body: JSON.stringify({ name: 'x', scopes: ['read'] }) }))).status).toBe(401);
  });
});

describe('enroll keys', () => {
  it('lets agents register with a web-created key until it is revoked', async () => {
    const r = await enrollPost(admin('/api/v1/admin/enroll-keys', { method: 'POST', body: JSON.stringify({ name: 'office' }) }));
    expect(r.status).toBe(201);
    const { key, item } = (await r.json()) as { key: string; item: { id: string } };
    expect(key).toMatch(/^asa_ek_[0-9a-f]{8}_[0-9a-f]{40}$/);
    const reg = load('register.v1.json');
    const send = () => register(req('/api/v1/agents/register', { token: key, method: 'POST', body: JSON.stringify(reg) }));
    expect((await send()).status).toBe(200);
    const [a] = await db.select().from(agents).where(eq(agents.id, reg.agent.id));
    expect(a.enrollKeyId).toBe(item.id);
    expect(a.keyIndex).toBeNull();
    const list = (await (await enrollGet(admin('/api/v1/admin/enroll-keys'))).json()).items as { id: string; agents: number }[];
    expect(list.find((x) => x.id === item.id)?.agents).toBe(1);
    // 撤銷後拒絕
    expect((await enrollDelete(admin(`/api/v1/admin/enroll-keys/${item.id}`, { method: 'DELETE' }), params({ id: item.id }))).status).toBe(200);
    expect((await send()).status).toBe(401);
    // 註冊金鑰不能當管理 token
    expect((await actionsGet(req('/api/v1/actions', { token: key }))).status).toBe(401);
  });
});

describe('install scripts', () => {
  it('serves scripts with this hub as the default enrollment target', async () => {
    const sh = await installSh(req('/install.sh'));
    expect(sh.status).toBe(200);
    const text = await sh.text();
    expect(text).toContain('DEFAULT_HUB="http://localhost:3000"');
    expect(text.startsWith('#!/bin/sh')).toBe(true);
    process.env.ASA_HUB_PUBLIC_URL = 'https://hub.example.com/';
    const ps = await (await installPs1(req('/install.ps1'))).text();
    expect(ps).toContain("$DefaultHub = 'https://hub.example.com'");
    delete process.env.ASA_HUB_PUBLIC_URL;
    // 惡意 Host 不會被塞進腳本
    const evil = await (await installSh(req('/install.sh', { headers: { host: 'x";rm -rf /;"' } }))).text();
    expect(evil).toContain('DEFAULT_HUB=""');
  });

  it('validates hub URLs, CSV cells and version ordering', () => {
    expect(safeHubUrl('https://hub.example.com:8443/asa/')).toBe('https://hub.example.com:8443/asa');
    expect(safeHubUrl('https://hub.example.com/$(id)')).toBeNull();
    expect(safeHubUrl("http://a'b")).toBeNull();
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell(null)).toBe('');
    expect(toCsv(['a'], [[1]])).toBe('﻿a\r\n1\r\n');
    expect(newer('0.2.0', '0.1.9')).toBe(true);
    expect(newer('0.10.0', '0.9.0')).toBe(true);
    expect(newer('0.2.0-rc1', '0.2.0')).toBe(false);
    expect(newer('0.2.0', '0.2.0-rc1')).toBe(true);
    expect(newer('0.1.0', '0.1.0')).toBe(false);
  });
});
