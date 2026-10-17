// 通知：祕密加密與遮罩、syslog／CEF 格式、管理 API、偵測新事件（不重複、不補發規則建立前的）、送出與重試、各種頻道。
import dgram from 'node:dgram';
import { createHmac, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { GET as notifyGet, PUT as notifyPut } from '@/app/api/v1/admin/notifications/route';
import { POST as channelPost } from '@/app/api/v1/admin/notifications/channels/route';
import { DELETE as channelDelete, PUT as channelPut } from '@/app/api/v1/admin/notifications/channels/[id]/route';
import { POST as channelTest } from '@/app/api/v1/admin/notifications/channels/[id]/test/route';
import { POST as rulePost } from '@/app/api/v1/admin/notifications/rules/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { POST as report } from '@/app/api/v1/ingest/report/route';
import { agents, auditLog, notificationChannels, notificationLog, notificationRules, notificationSeen, settings } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { decryptConfig, maskConfig, prepareConfig, syslogLine } from '@/lib/notify/channels';
import { decrypt, encrypt, resetSecretKeyForTests, secretKey } from '@/lib/notify/secret';
import { runNotifications } from '@/lib/notify/service';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const admin = { authorization: 'Bearer test-admin' };
const AGENT = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
const HOOK = 'https://hooks.example.com/services/T000/B000/secret-token';

function clientPost(pathname: string, body: unknown) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer client-a' },
    body: JSON.stringify(body),
  });
}

const ctx = (id: string) => ({ params: Promise.resolve({ id }) });

async function createChannel(body: unknown): Promise<string> {
  const r = await channelPost(req('/api/v1/admin/notifications/channels', { method: 'POST', body, headers: admin }));
  expect(r.status).toBe(201);
  return ((await r.json()) as { id: string }).id;
}

async function createRule(body: unknown): Promise<string> {
  const r = await rulePost(req('/api/v1/admin/notifications/rules', { method: 'POST', body, headers: admin }));
  expect(r.status).toBe(201);
  return ((await r.json()) as { id: string }).id;
}

async function ingestReport(fresh = false) {
  const rep = load('report.v1.json');
  rep.report_id = randomUUID();
  // fresh：換新的 finding id＝新問題
  if (fresh) for (const f of rep.findings) f.id = `f_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
  rep.finished_at = new Date().toISOString();
  expect((await report(clientPost('/api/v1/ingest/report', rep))).status).toBe(200);
}

function fakeFetch(fail = false) {
  const calls: { url: string; body: string; headers: Record<string, string> }[] = [];
  const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), body: String(init?.body ?? ''), headers: (init?.headers ?? {}) as Record<string, string> });
    return fail ? new Response('nope', { status: 500 }) : new Response('ok');
  });
  return { f: f as unknown as typeof fetch, calls };
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
  resetEnvForTests();
  await register(clientPost('/api/v1/agents/register', load('register.v1.json')));
});

beforeEach(async () => {
  delete process.env.ASA_HUB_SECRETS_KEY;
  resetEnvForTests();
  resetRateLimitsForTests();
  resetSecretKeyForTests();
  await db.delete(notificationLog);
  await db.delete(notificationSeen);
  await db.delete(notificationRules);
  await db.delete(notificationChannels);
  await db.delete(auditLog);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

describe('secrets and formats', () => {
  it('encrypts secrets, keeps them on update when left blank, and masks them for the UI', async () => {
    const key = await secretKey(db);
    expect(decrypt(key, encrypt(key, 'hello'))).toBe('hello');
    // 金鑰存在 settings，第二次拿到同一把
    resetSecretKeyForTests();
    expect((await secretKey(db)).equals(key)).toBe(true);

    const cfg = prepareConfig('webhook', { url: HOOK, hmacSecret: 's3cret' }, key);
    expect(JSON.stringify(cfg)).not.toContain('secret-token');
    expect(JSON.stringify(cfg)).not.toContain('s3cret');
    expect(decryptConfig('webhook', cfg, key)).toEqual({ url: HOOK, hmacSecret: 's3cret' });
    expect(maskConfig('webhook', cfg, key)).toEqual({ url: 'https://hooks.example.com/…', hmacSecret: '••••' });
    // 更新時祕密留空＝沿用
    const again = prepareConfig('webhook', { url: '' }, key, cfg);
    expect(decryptConfig('webhook', again, key)).toEqual({ url: HOOK, hmacSecret: 's3cret' });
    expect(() => prepareConfig('slack', { url: 'http://insecure.example.com' }, key)).toThrow();
    expect(() => prepareConfig('email', { host: 'smtp.example.com', from: 'a@example.com', to: [] }, key)).toThrow();
  });

  it('uses an explicit key from the environment', async () => {
    process.env.ASA_HUB_SECRETS_KEY = 'ab'.repeat(32);
    resetEnvForTests();
    resetSecretKeyForTests();
    expect((await secretKey(db)).toString('hex')).toBe('ab'.repeat(32));
    process.env.ASA_HUB_SECRETS_KEY = 'too-short';
    resetEnvForTests();
    resetSecretKeyForTests();
    await expect(secretKey(db)).rejects.toThrow(/32 bytes/);
  });

  it('formats RFC 5424 and CEF lines with escaping', () => {
    const m = { event: 'finding', title: 'A|B', lines: ['x=1', 'line2'], link: 'https://hub/f', severity: 'critical' };
    const at = new Date('2026-10-18T00:00:00Z');
    expect(syslogLine(m, 'rfc5424', 'hub host', '0.5.0', at)).toBe('<130>1 2026-10-18T00:00:00.000Z hub-host ai-security-monitor-hub - finding - A|B | x=1 | line2 | https://hub/f');
    const cef = syslogLine(m, 'cef', 'hub', '0.5.0', at);
    expect(cef).toContain('CEF:0|ai-security-monitor|Security Hub|0.5.0|finding|A\\|B|10|msg=x\\=1\\nline2 request=https://hub/f');
  });
});

describe('admin API', () => {
  it('needs admin, validates input, never returns secrets, and audits without config contents', async () => {
    expect((await notifyGet(req('/api/v1/admin/notifications', { headers: { authorization: 'Bearer client-a' } }))).status).toBe(401);
    expect((await channelPost(req('/api/v1/admin/notifications/channels', { method: 'POST', body: { kind: 'slack', name: 'x', config: { url: HOOK } } }))).status).toBe(401);
    const bad = await channelPost(req('/api/v1/admin/notifications/channels', { method: 'POST', body: { kind: 'slack', name: 'x', config: { url: 'nope' } }, headers: admin }));
    expect(bad.status).toBe(400);
    expect((await bad.json()) as { error: string }).toMatchObject({ error: 'invalid_url' });

    const id = await createChannel({ kind: 'slack', name: 'SOC', config: { url: HOOK } });
    const view = await notifyGet(req('/api/v1/admin/notifications', { headers: admin }));
    const text = await view.text();
    expect(text).not.toContain('secret-token');
    expect(JSON.parse(text).channels[0]).toMatchObject({ id, kind: 'slack', name: 'SOC', target: 'https://hooks.example.com/…' });
    const audits = await db.select().from(auditLog).where(eq(auditLog.action, 'notification.channel_created'));
    expect(JSON.stringify(audits)).not.toContain('secret-token');

    // 規則要指到存在的頻道
    expect((await rulePost(req('/api/v1/admin/notifications/rules', { method: 'POST', body: { name: 'r', event: 'finding', channelIds: ['nope'] }, headers: admin }))).status).toBe(400);
    expect((await rulePost(req('/api/v1/admin/notifications/rules', { method: 'POST', body: { name: 'r', event: 'bogus', channelIds: [id] }, headers: admin }))).status).toBe(400);
    const ruleId = await createRule({ name: 'r', event: 'finding', channelIds: [id] });
    expect((await db.select().from(notificationRules).where(eq(notificationRules.id, ruleId)))[0].minSeverity).toBe('high');

    // 改名稱與停用；刪掉頻道後規則裡也拿掉
    expect((await channelPut(req(`/api/v1/admin/notifications/channels/${id}`, { method: 'PUT', body: { name: 'SOC 2', enabled: false }, headers: admin }), ctx(id))).status).toBe(200);
    expect((await channelDelete(req(`/api/v1/admin/notifications/channels/${id}`, { method: 'DELETE', headers: admin }), ctx(id))).status).toBe(200);
    expect((await db.select().from(notificationRules).where(eq(notificationRules.id, ruleId)))[0].channelIds).toEqual([]);

    const s = await notifyPut(req('/api/v1/admin/notifications', { method: 'PUT', body: { lang: 'en', hubUrl: 'https://hub.example.com/' }, headers: admin }));
    expect(((await s.json()) as { settings: unknown }).settings).toEqual({ lang: 'en', hubUrl: 'https://hub.example.com' });
    await db.delete(settings).where(eq(settings.key, 'notify.settings'));
  });

  it('sends a test message right away and reports failures', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    const id = await createChannel({ kind: 'discord', name: 'Ops', config: { url: HOOK } });
    const r = await channelTest(req(`/api/v1/admin/notifications/channels/${id}/test`, { method: 'POST', headers: admin }), ctx(id));
    expect(await r.json()).toEqual({ ok: true });
    expect(JSON.parse(calls[0].body).content).toContain('Ops');
    vi.stubGlobal('fetch', fakeFetch(true).f);
    const bad = await channelTest(req(`/api/v1/admin/notifications/channels/${id}/test`, { method: 'POST', headers: admin }), ctx(id));
    expect(await bad.json()).toEqual({ ok: false, error: 'HTTP 500' });
    expect((await db.select().from(notificationChannels))[0].lastError).toBe('HTTP 500');
    vi.unstubAllGlobals();
  });
});

describe('detection and delivery', () => {
  it('notifies new findings once per rule, signs webhooks, and ignores findings from before the rule', async () => {
    // 規則建立之前就有的問題不通知
    await ingestReport();
    const ch = await createChannel({ kind: 'webhook', name: 'SIEM', config: { url: HOOK, hmacSecret: 'k' } });
    await createRule({ name: 'critical', event: 'finding', minSeverity: 'critical', channelIds: [ch] });
    const { f, calls } = fakeFetch();
    expect(await runNotifications(db, new Date(), { fetch: f })).toEqual({ queued: 0, sent: 0, failed: 0 });
    // 同樣的問題再回報一次也不算新的
    await ingestReport();
    expect((await runNotifications(db, new Date(), { fetch: f })).queued).toBe(0);

    await ingestReport(true);
    const r = await runNotifications(db, new Date(), { fetch: f });
    expect(r).toEqual({ queued: 1, sent: 1, failed: 0 });
    const body = JSON.parse(calls[0].body);
    expect(body).toMatchObject({ event: 'finding', severity: 'critical' });
    expect(body.title).toContain('2');
    expect(body.lines.join('\n')).toContain('Redis');
    // HMAC：時間戳＋本文
    const h = calls[0].headers;
    expect(h['x-aism-signature']).toBe(`sha256=${createHmac('sha256', 'k').update(`${h['x-aism-timestamp']}.${calls[0].body}`).digest('hex')}`);
    // 下一輪不重複通知
    expect((await runNotifications(db, new Date(), { fetch: f })).queued).toBe(0);
  });

  it('retries failed deliveries three times and records the error on the channel', async () => {
    const ch = await createChannel({ kind: 'slack', name: 'Broken', config: { url: HOOK } });
    await createRule({ name: 'all', event: 'finding', minSeverity: 'info', channelIds: [ch] });
    await ingestReport(true);
    const { f } = fakeFetch(true);
    expect((await runNotifications(db, new Date(), { fetch: f })).queued).toBe(1);
    await runNotifications(db, new Date(), { fetch: f });
    expect((await runNotifications(db, new Date(), { fetch: f })).failed).toBe(1);
    const [row] = await db.select().from(notificationLog);
    expect(row).toMatchObject({ status: 'failed', attempts: 3, error: 'HTTP 500' });
    expect((await db.select().from(notificationChannels))[0].lastError).toBe('HTTP 500');
  });

  it('emails through SMTP and sends syslog over UDP', async () => {
    const sent: Record<string, unknown>[] = [];
    const mail = await createChannel({ kind: 'email', name: 'Mail', config: { host: 'smtp.example.com', port: 587, user: 'u', pass: 'p', from: 'hub@example.com', to: ['soc@example.com'] } });
    const server = dgram.createSocket('udp4');
    const got = new Promise<string>((resolve) => server.on('message', (b) => resolve(b.toString())));
    await new Promise<void>((resolve) => server.bind(0, '127.0.0.1', () => resolve()));
    const port = (server.address() as { port: number }).port;
    const sys = await createChannel({ kind: 'syslog', name: 'Syslog', config: { host: '127.0.0.1', port, protocol: 'udp', format: 'cef' } });
    await createRule({ name: 'joined', event: 'host_joined', channelIds: [mail, sys] });
    // 新主機：首次出現時間在規則之後
    await db.update(agents).set({ firstSeenAt: new Date(Date.now() + 1000) }).where(eq(agents.id, AGENT));
    const r = await runNotifications(db, new Date(Date.now() + 2000), {
      smtpTransport: (cfg) => {
        expect(cfg).toMatchObject({ host: 'smtp.example.com', port: 587, auth: { user: 'u', pass: 'p' } });
        return { sendMail: async (m) => void sent.push(m) };
      },
    });
    expect(r).toEqual({ queued: 2, sent: 2, failed: 0 });
    expect(sent[0]).toMatchObject({ from: 'hub@example.com', to: 'soc@example.com' });
    expect(String(sent[0].text)).toContain('demo-host');
    expect(await got).toMatch(/^<134>1 .* host_joined - CEF:0\|ai-security-monitor\|/);
    server.close();
  });

  it('reports hosts that stop checking in after the rule exists, and the daily digest at its hour', async () => {
    const { f, calls } = fakeFetch();
    const ch = await createChannel({ kind: 'slack', name: 'S', config: { url: HOOK } });
    await createRule({ name: 'offline', event: 'host_offline', params: { minutes: 30 }, channelIds: [ch] });
    const ruleAt = (await db.select().from(notificationRules))[0].createdAt;
    await db.update(agents).set({ lastSeenAt: new Date(ruleAt.getTime() + 1000) }).where(eq(agents.id, AGENT));
    // 還沒超過 30 分鐘
    expect((await runNotifications(db, new Date(ruleAt.getTime() + 10 * 60_000), { fetch: f })).queued).toBe(0);
    expect((await runNotifications(db, new Date(ruleAt.getTime() + 45 * 60_000), { fetch: f })).queued).toBe(1);
    expect(JSON.parse(calls[0].body).text).toContain('demo-host');

    await createRule({ name: 'digest', event: 'daily_digest', params: { hour: 8 }, channelIds: [ch] });
    const at8 = new Date('2030-01-01T08:05:00Z');
    expect((await runNotifications(db, new Date('2030-01-01T07:05:00Z'), { fetch: f })).queued).toBe(0);
    expect((await runNotifications(db, at8, { fetch: f })).queued).toBe(1);
    expect((await runNotifications(db, new Date('2030-01-01T08:30:00Z'), { fetch: f })).queued).toBe(0);
    expect(JSON.parse(calls.at(-1)!.body).text).toContain('每日摘要');
    await db.update(agents).set({ lastSeenAt: new Date() }).where(eq(agents.id, AGENT));
  });
});
