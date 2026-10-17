// 免金鑰加入＋Hub 身分：申請 → 輪詢 → 核准 → 拿綁定金鑰註冊 → 已領取；自動核准網段、限流、到期、CSRF、金鑰綁定。
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { POST as login } from '@/app/api/auth/login/route';
import { POST as decidePost } from '@/app/api/v1/admin/enroll-requests/decide/route';
import { GET as listGet } from '@/app/api/v1/admin/enroll-requests/route';
import { GET as settingsGet, PUT as settingsPut } from '@/app/api/v1/admin/enroll-settings/route';
import { GET as pollGet } from '@/app/api/v1/agents/enroll-request/[id]/route';
import { POST as createPost } from '@/app/api/v1/agents/enroll-request/route';
import { GET as actionsPoll } from '@/app/api/v1/agents/me/actions/route';
import { POST as heartbeat } from '@/app/api/v1/agents/me/heartbeat/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { GET as identityGet } from '@/app/api/v1/hub/identity/route';
import { auditLog, enrollKeys, enrollmentRequests, settings } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { randomToken } from '@/lib/auth/crypto';
import { resetTokenTouchForTests } from '@/lib/auth/tokens';
import type { DB } from '@/lib/db';
import { approvalMessage, FINGERPRINT_RE, pkcs8FromSeed, resetHubIdentityForTests, verifyWithRawKey } from '@/lib/enroll/identity';
import { CREATES_PER_WINDOW, resetEnrollSecretsForTests, setPendingCapForTests } from '@/lib/enroll/store';
import { resetEnvForTests } from '@/lib/env';
import { setPeerIpHookForTests } from '@/lib/http';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { createTestDb } from '../helpers/db';
import { cookieFrom } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const IDENTITY = load('hub-identity.v1.json');
const ENROLL = load('enroll-request.v1.json');

type Init = { method?: string; body?: unknown; token?: string; headers?: Record<string, string> };
const req = (url: string, init: Init = {}) =>
  new Request(`http://localhost:3000${url}`, {
    method: init.method ?? 'GET',
    headers: {
      'content-type': 'application/json',
      host: 'localhost:3000',
      ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
      ...(init.headers ?? {}),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
const admin = (url: string, init: Init = {}) => req(url, { ...init, token: 'test-admin' });
const params = <T extends Record<string, string>>(p: T) => ({ params: Promise.resolve(p) });

let n = 0;
/** 每次一台新的 agent（不同 id、不同 secret）。 */
function newRequest(over: Record<string, unknown> = {}) {
  n += 1;
  return { ...ENROLL, agent: { ...ENROLL.agent, id: `agent-enroll-${n}`, hostname: `host-${n}` }, request_secret: randomToken(32), ...over };
}

const create = (body: unknown, headers: Record<string, string> = {}) => createPost(req('/api/v1/agents/enroll-request', { method: 'POST', body, headers }));
const poll = (id: string, secret: string, headers: Record<string, string> = {}) =>
  pollGet(req(`/api/v1/agents/enroll-request/${id}`, { token: secret, headers }), params({ id }));
const decide = (ids: string[], decision: 'approve' | 'reject', reason?: string) =>
  decidePost(admin('/api/v1/admin/enroll-requests/decide', { method: 'POST', body: { ids, decision, ...(reason ? { reason } : {}) } }));
const setCidrs = (list: unknown[]) => settingsPut(admin('/api/v1/admin/enroll-settings', { method: 'PUT', body: { auto_approve_cidrs: list } }));

async function audits(action: string, targetId?: string) {
  const rows = await db.select().from(auditLog).where(eq(auditLog.action, action));
  return targetId ? rows.filter((r) => r.targetId === targetId) : rows;
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
  // 用契約的測試金鑰（seed＝32 bytes 0x07）當 Hub 身分，簽章才會跟 contract/*.json 逐字相同
  const der = pkcs8FromSeed(Buffer.alloc(32, 7));
  await db.insert(settings).values({ key: 'hub_identity', value: { public_key: IDENTITY.public_key, private_key: der.toString('base64url') } });
});

beforeEach(() => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
  delete process.env.ASA_HUB_ENROLL_REQUESTS;
  delete process.env.ASA_HUB_TRUST_PROXY;
  delete process.env.ASA_HUB_PUBLIC_URL;
  resetEnvForTests();
  resetThrottleForTests();
  resetRateLimitsForTests();
  resetTokenTouchForTests();
  resetHubIdentityForTests();
  resetEnrollSecretsForTests();
  setPendingCapForTests();
});

afterEach(() => {
  setPeerIpHookForTests(false);
});

describe('hub identity', () => {
  it('serves the public key and signs a nonce', async () => {
    const r = await identityGet(req(`/api/v1/hub/identity?nonce=${IDENTITY.nonce}`));
    expect(r.status).toBe(200);
    const b = await r.json();
    expect(b).toMatchObject({ algorithm: 'ed25519', public_key: IDENTITY.public_key, fingerprint: IDENTITY.fingerprint, enrollment: { keyless: true }, nonce: IDENTITY.nonce });
    expect(b.fingerprint).toMatch(FINGERPRINT_RE);
    // Ed25519 是確定性簽章：跟契約檔逐字相同
    expect(b.signature).toBe(IDENTITY.signature);
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(b.public_key, 'base64url')]);
    const key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    expect(crypto.verify(null, Buffer.from(`asa-hub-identity|v1|${b.nonce}|${b.fingerprint}`), key, Buffer.from(b.signature, 'base64url'))).toBe(true);
    // 沒 nonce 就不簽
    const plain = await (await identityGet(req('/api/v1/hub/identity'))).json();
    expect(plain.signature).toBeUndefined();
    expect(plain.nonce).toBeUndefined();
  });

  it('rejects bad nonces, rate-limits, and reports keyless off', async () => {
    for (const bad of ['short', 'x'.repeat(129), 'has space in it!!!', '%27%3B--aaaaaaaaaaaa']) {
      const r = await identityGet(req(`/api/v1/hub/identity?nonce=${bad}`));
      expect(r.status).toBe(400);
      expect((await r.json()).error).toBe('bad_nonce');
    }
    process.env.ASA_HUB_ENROLL_REQUESTS = 'off';
    expect((await (await identityGet(req('/api/v1/hub/identity'))).json()).enrollment.keyless).toBe(false);
    for (let i = 0; i < 115; i++) await identityGet(req('/api/v1/hub/identity'));
    expect((await identityGet(req('/api/v1/hub/identity'))).status).toBe(429);
  });
});

describe('keyless enrollment lifecycle', () => {
  it('pending → approve → credentials → register (pinned) → claimed → credentials stop', async () => {
    const r = await create(ENROLL, { 'x-asa-agent-id': ENROLL.agent.id });
    expect(r.status).toBe(201);
    const c = await r.json();
    expect(c).toMatchObject({ status: 'pending', auto_approved: false, request_code: 'ENDY-Z24W', poll_interval_s: 15, hub: { fingerprint: IDENTITY.fingerprint } });
    expect(c.request_id).toMatch(/^rq_[0-9a-f]{24}$/);
    expect(await audits('enroll_request.created', c.request_id)).toHaveLength(1);

    // secret 只存 sha256
    const [row] = await db.select().from(enrollmentRequests).where(eq(enrollmentRequests.id, c.request_id));
    expect(row.secretHash).toBe(crypto.createHash('sha256').update(ENROLL.request_secret).digest('hex'));
    expect(JSON.stringify(row)).not.toContain(ENROLL.request_secret);

    // 冪等：同一台同一 secret 再送一次 → 同一筆
    const again = await create(ENROLL);
    expect(again.status).toBe(200);
    expect((await again.json()).request_id).toBe(c.request_id);

    // 核准前輪詢：沒有憑證
    const p1 = await (await poll(c.request_id, ENROLL.request_secret)).json();
    expect(p1).toMatchObject({ request_id: c.request_id, status: 'pending', request_code: 'ENDY-Z24W' });
    expect(p1.credentials).toBeUndefined();

    // 管理清單不洩漏 secret 雜湊／金鑰
    const list = await (await listGet(admin('/api/v1/admin/enroll-requests'))).json();
    const item = list.items.find((x: { id: string }) => x.id === c.request_id);
    expect(item).toMatchObject({ status: 'pending', hostname: 'demo-host', request_code: 'ENDY-Z24W', known_agent: false, source_ip: 'local' });
    const text = JSON.stringify(list);
    expect(text).not.toContain(row.secretHash);
    expect(text).not.toMatch(/secret|key_hash|enroll_key|client_key|credentials/);
    expect(list.counts.pending).toBeGreaterThanOrEqual(1);

    // 核准
    const d = await decide([c.request_id], 'approve');
    expect(d.status).toBe(200);
    const dj = await d.json();
    expect(dj.updated).toBe(1);
    expect(JSON.stringify(dj)).not.toMatch(/client_key|key_hash/);
    expect(await audits('enroll_request.approved', c.request_id)).toHaveLength(1);
    // 再核准一次：不是 pending，不動
    expect((await (await decide([c.request_id], 'approve')).json()).updated).toBe(0);

    const p2 = await (await poll(c.request_id, ENROLL.request_secret)).json();
    expect(p2.status).toBe('approved');
    const cred = p2.credentials;
    expect(cred.agent_id).toBe(ENROLL.agent.id);
    expect(cred.client_key).toMatch(/^asa_ek_[0-9a-f]{8}_[0-9a-f]{40}$/);
    expect(cred.hub_fingerprint).toBe(IDENTITY.fingerprint);
    expect(verifyWithRawKey(IDENTITY.public_key, approvalMessage(c.request_id, cred.agent_id, cred.client_key), cred.signature)).toBe(true);
    // 金鑰明文不在資料庫
    const [k] = await db.select().from(enrollKeys).where(eq(enrollKeys.boundAgentId, ENROLL.agent.id));
    expect(k.keyHash).toBe(crypto.createHash('sha256').update(cred.client_key).digest('hex'));
    expect(k.name).toBe('demo-host (enrollment request)');

    // 用拿到的金鑰正常註冊（含 agent token 釘選）
    const agentToken = randomToken(24);
    const regBody = { agent: ENROLL.agent, accept_remote_actions: false };
    const reg = await register(req('/api/v1/agents/register', { method: 'POST', token: cred.client_key, body: regBody, headers: { 'x-asa-agent-token': agentToken } }));
    expect(reg.status).toBe(200);
    expect((await reg.json()).pinned).toBe(true);
    const [claimed] = await db.select().from(enrollmentRequests).where(eq(enrollmentRequests.id, c.request_id));
    expect(claimed.claimedAt).not.toBeNull();
    // 釘選沒有被削弱：換 token 就 403
    const bad = await register(req('/api/v1/agents/register', { method: 'POST', token: cred.client_key, body: regBody, headers: { 'x-asa-agent-token': randomToken(24) } }));
    expect(bad.status).toBe(403);

    // 已領取 10 分鐘內還回憑證（agent 重試用），之後就不回
    expect((await (await poll(c.request_id, ENROLL.request_secret)).json()).credentials).toBeDefined();
    await db.update(enrollmentRequests).set({ claimedAt: new Date(Date.now() - 11 * 60_000) }).where(eq(enrollmentRequests.id, c.request_id));
    const p3 = await (await poll(c.request_id, ENROLL.request_secret)).json();
    expect(p3.status).toBe('approved');
    expect(p3.credentials).toBeUndefined();

    // 綁定：同一把金鑰替別的 agent id 上傳 → 403＋稽核
    const other = await register(req('/api/v1/agents/register', { method: 'POST', token: cred.client_key, body: { agent: { ...ENROLL.agent, id: 'someone-else' } } }));
    expect(other.status).toBe(403);
    expect((await other.json()).error).toBe('key_bound_to_other_agent');
    expect(await audits('ingest.register.key_bound_to_other_agent')).not.toHaveLength(0);
    const hb = await heartbeat(
      req('/api/v1/agents/me/heartbeat', { method: 'POST', token: cred.client_key, body: { agent_id: 'someone-else', ts: new Date().toISOString(), version: '0.1.0' } }),
    );
    expect(hb.status).toBe(403);
    const ap = await actionsPoll(req('/api/v1/agents/me/actions', { token: cred.client_key, headers: { 'x-asa-agent-id': 'someone-else', 'x-asa-agent-token': agentToken } }));
    expect(ap.status).toBe(403);
    // 自己的 agent id 照常
    const mine = await actionsPoll(req('/api/v1/agents/me/actions', { token: cred.client_key, headers: { 'x-asa-agent-id': ENROLL.agent.id, 'x-asa-agent-token': agentToken } }));
    expect(mine.status).toBe(200);

    // 之後同一台再申請 → 清單標示「重新加入」
    const re = await (await create({ ...ENROLL, request_secret: randomToken(32) })).json();
    const list2 = await (await listGet(admin('/api/v1/admin/enroll-requests'))).json();
    expect(list2.items.find((x: { id: string }) => x.id === re.request_id).known_agent).toBe(true);
  });

  it('answers 404 for unknown ids and wrong secrets alike', async () => {
    const body = newRequest();
    const c = await (await create(body)).json();
    for (const r of [
      await poll(c.request_id, randomToken(32)),
      await poll('rq_000000000000000000000000', body.request_secret),
      await poll('nope', body.request_secret),
      await pollGet(req(`/api/v1/agents/enroll-request/${c.request_id}`), params({ id: c.request_id })),
    ]) {
      expect(r.status).toBe(404);
      expect(await r.json()).toEqual({ error: 'not_found' });
    }
  });

  it('rejects with a reason', async () => {
    const body = newRequest();
    const c = await (await create(body)).json();
    const d = await (await decide([c.request_id], 'reject', '不認識這台')).json();
    expect(d.updated).toBe(1);
    const p = await (await poll(c.request_id, body.request_secret)).json();
    expect(p).toMatchObject({ status: 'rejected', reason: '不認識這台' });
    expect(p.credentials).toBeUndefined();
    expect(await audits('enroll_request.rejected', c.request_id)).toHaveLength(1);
    // 拒絕後不能再核准
    expect((await (await decide([c.request_id], 'approve')).json()).updated).toBe(0);
  });

  it('validates input, header agent id and hub fingerprint; can be disabled', async () => {
    expect((await create({ ...newRequest(), request_secret: 'short' })).status).toBe(400);
    expect((await create({ agent: {} })).status).toBe(400);
    const r = await create(newRequest(), { 'x-asa-agent-id': 'different' });
    expect(r.status).toBe(400);
    expect((await r.json()).rule).toBe('agent_id_mismatch');
    const fp = await create(newRequest({ hub_fingerprint: 'AAAA-BBBB-CCCC-DDDD-EEEE' }));
    expect(fp.status).toBe(409);
    expect(await fp.json()).toEqual({ error: 'hub_fingerprint_mismatch', fingerprint: IDENTITY.fingerprint });
    process.env.ASA_HUB_ENROLL_REQUESTS = '0';
    const off = await create(newRequest());
    expect(off.status).toBe(403);
    expect((await off.json()).error).toBe('enroll_requests_disabled');
  });

  it('bulk approves several requests at once', async () => {
    const a = await (await create(newRequest())).json();
    const b = await (await create(newRequest())).json();
    const d = await (await decide([a.request_id, b.request_id, 'rq_ffffffffffffffffffffffff'], 'approve')).json();
    expect(d.updated).toBe(2);
    expect((await decidePost(admin('/api/v1/admin/enroll-requests/decide', { method: 'POST', body: { ids: [], decision: 'approve' } }))).status).toBe(400);
    expect((await decidePost(admin('/api/v1/admin/enroll-requests/decide', { method: 'POST', body: { ids: ['x'], decision: 'maybe' } }))).status).toBe(400);
  });
});

describe('auto-approve networks', () => {
  it('approves only when the TCP peer (not X-Forwarded-For) is inside a configured CIDR', async () => {
    const s = await setCidrs(['192.0.2.0/24', ' 2001:db8::/32 ', '']);
    expect(s.status).toBe(200);
    expect((await s.json()).auto_approve_cidrs).toEqual(['192.0.2.0/24', '2001:db8::/32']);
    const changed = await audits('enroll_settings.updated');
    expect(changed.at(-1)?.details).toMatchObject({ after: ['192.0.2.0/24', '2001:db8::/32'] });

    // 沒裝 hook：就算帶了標頭也不自動核准
    const noHook = await (await create(newRequest(), { 'x-asa-peer-ip': '192.0.2.55' })).json();
    expect(noHook.status).toBe('pending');
    // 偽造 X-Forwarded-For（沒開 trust proxy）→ 不算
    const spoof = await (await create(newRequest(), { 'x-forwarded-for': '192.0.2.55' })).json();
    expect(spoof.status).toBe('pending');

    setPeerIpHookForTests(true);
    const outside = await (await create(newRequest(), { 'x-asa-peer-ip': '198.51.100.7', 'x-forwarded-for': '192.0.2.55' })).json();
    expect(outside.status).toBe('pending');
    const body = newRequest();
    const inside = await create(body, { 'x-asa-peer-ip': '::ffff:192.0.2.55' });
    expect(inside.status).toBe(201);
    const ij = await inside.json();
    expect(ij).toMatchObject({ status: 'approved', auto_approved: true });
    const [row] = await db.select().from(enrollmentRequests).where(eq(enrollmentRequests.id, ij.request_id));
    expect(row.decidedBy).toBe('auto:192.0.2.0/24');
    expect(row.sourceIp).toBe('192.0.2.55');
    expect(await audits('enroll_request.auto_approved', ij.request_id)).toHaveLength(1);
    expect((await (await poll(ij.request_id, body.request_secret)).json()).credentials.agent_id).toBe(body.agent.id);
    const v6 = await (await create(newRequest(), { 'x-asa-peer-ip': '2001:db8:1::9' })).json();
    expect(v6.status).toBe('approved');

    // 開了 trust proxy：看 X-Forwarded-For 最後一個
    setPeerIpHookForTests(false);
    process.env.ASA_HUB_TRUST_PROXY = '1';
    resetEnvForTests();
    const proxied = await (await create(newRequest(), { 'x-forwarded-for': '192.0.2.200, 203.0.113.9' })).json();
    expect(proxied.status).toBe('pending');
    const proxied2 = await (await create(newRequest(), { 'x-forwarded-for': '203.0.113.9, 192.0.2.200' })).json();
    expect(proxied2.status).toBe('approved');
  });

  it('does not auto-approve an existing agent whose identity was never pinned', async () => {
    await setCidrs(['192.0.2.0/24']);
    const body = newRequest();
    // 舊主機：用環境變數金鑰註冊、沒帶 agent token（沒釘選）
    expect((await register(req('/api/v1/agents/register', { method: 'POST', token: 'client-a', body: { agent: body.agent } }))).status).toBe(200);
    setPeerIpHookForTests(true);
    const r = await (await create(body, { 'x-asa-peer-ip': '192.0.2.10' })).json();
    expect(r.status).toBe('pending');
  });

  it('validates CIDRs', async () => {
    for (const [value, code] of [
      ['not-an-ip', 'bad_cidr'],
      ['10.0.0.0/33', 'bad_cidr'],
      ['10.0.0.0/x', 'bad_cidr'],
      ['300.1.1.1', 'bad_cidr'],
      ['10.0.0.0/7', 'cidr_too_broad'],
      ['0.0.0.0/0', 'cidr_too_broad'],
      ['::/8', 'cidr_too_broad'],
    ] as const) {
      const r = await setCidrs(['192.168.0.0/16', value]);
      expect(r.status).toBe(400);
      expect(await r.json()).toEqual({ error: code, value });
    }
    expect((await setCidrs(Array.from({ length: 65 }, (_, i) => `10.0.${i}.0/24`))).status).toBe(400);
    expect((await settingsPut(admin('/api/v1/admin/enroll-settings', { method: 'PUT', body: { auto_approve_cidrs: '10.0.0.0/8' } }))).status).toBe(400);
    const ok = await (await setCidrs(['192.168.1.77/24', '10.1.2.3', '2001:DB8::1/48', '192.168.1.0/24'])).json();
    expect(ok.auto_approve_cidrs).toEqual(['192.168.1.0/24', '10.1.2.3/32', '2001:db8::/48']);
    await setCidrs([]);
  });

  it('settings show fingerprint, mDNS status and the DNS SRV record', async () => {
    process.env.ASA_HUB_PUBLIC_URL = 'https://hub.corp.acme.com';
    const s = await (await settingsGet(admin('/api/v1/admin/enroll-settings'))).json();
    expect(s.hub).toMatchObject({ fingerprint: IDENTITY.fingerprint, public_url: 'https://hub.corp.acme.com' });
    expect(s.srv).toMatchObject({ name: '_ai-security-monitor._tcp.corp.acme.com', target: 'hub.corp.acme.com', port: 443, txt: ['url=https://hub.corp.acme.com', `fp=${IDENTITY.fingerprint}`] });
    expect(s.mdns).toMatchObject({ enabled: false, running: false });
    expect(s.enroll_requests_enabled).toBe(true);
    expect(s.peer_ip_available).toBe(false);
    expect(JSON.stringify(s)).not.toContain('private');
  });
});

describe('abuse limits and expiry', () => {
  it('rate-limits creates per source IP', async () => {
    for (let i = 0; i < CREATES_PER_WINDOW; i++) expect((await create(newRequest())).status).toBe(201);
    const r = await create(newRequest());
    expect(r.status).toBe(429);
    expect(r.headers.get('retry-after')).toBe('600');
  });

  it('rate-limits poll failures per source IP', async () => {
    const body = newRequest();
    const c = await (await create(body)).json();
    for (let i = 0; i < 30; i++) expect((await poll(c.request_id, randomToken(32))).status).toBe(404);
    // 失敗太多之後，連正確的 secret 也先擋（擋暴力猜測）
    expect((await poll(c.request_id, body.request_secret)).status).toBe(429);
    resetRateLimitsForTests();
    expect((await poll(c.request_id, body.request_secret)).status).toBe(200);
  });

  it('caps the number of pending requests', async () => {
    const pending = (await db.select().from(enrollmentRequests).where(eq(enrollmentRequests.status, 'pending'))).length;
    setPendingCapForTests(pending + 1);
    expect((await create(newRequest())).status).toBe(201);
    const r = await create(newRequest());
    expect(r.status).toBe(503);
    expect((await r.json()).error).toBe('too_many_pending');
  });

  it('expires stale pending and unclaimed approved requests (and revokes their keys)', async () => {
    const a = newRequest();
    const ca = await (await create(a)).json();
    await db.update(enrollmentRequests).set({ createdAt: new Date(Date.now() - 8 * 86_400_000) }).where(eq(enrollmentRequests.id, ca.request_id));
    expect((await (await poll(ca.request_id, a.request_secret)).json()).status).toBe('expired');
    expect((await (await decide([ca.request_id], 'approve')).json()).updated).toBe(0);

    const b = newRequest();
    const cb = await (await create(b)).json();
    await decide([cb.request_id], 'approve');
    const cred = (await (await poll(cb.request_id, b.request_secret)).json()).credentials;
    await db.update(enrollmentRequests).set({ decidedAt: new Date(Date.now() - 8 * 86_400_000) }).where(eq(enrollmentRequests.id, cb.request_id));
    const pb = await (await poll(cb.request_id, b.request_secret)).json();
    expect(pb.status).toBe('expired');
    expect(pb.credentials).toBeUndefined();
    const [row] = await db.select().from(enrollmentRequests).where(eq(enrollmentRequests.id, cb.request_id));
    const [key] = await db.select().from(enrollKeys).where(eq(enrollKeys.id, row.enrollKeyId!));
    expect(key.revokedAt).not.toBeNull();
    expect((await register(req('/api/v1/agents/register', { method: 'POST', token: cred.client_key, body: { agent: b.agent } }))).status).toBe(401);
  });
});

describe('admin auth', () => {
  it('requires admin and blocks cookie writes without the CSRF header', async () => {
    expect((await listGet(req('/api/v1/admin/enroll-requests'))).status).toBe(401);
    expect((await listGet(req('/api/v1/admin/enroll-requests', { token: 'client-a' }))).status).toBe(401);
    expect((await settingsGet(req('/api/v1/admin/enroll-settings'))).status).toBe(401);
    const c = await (await create(newRequest())).json();

    const ok = await login(new Request('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', host: 'localhost:3000', 'x-asa-request': '1', 'sec-fetch-site': 'same-origin' },
      body: JSON.stringify({ key: 'test-admin' }),
    }));
    const cookie = cookieFrom(ok, 'asa_admin')!;
    expect(cookie).toBeTruthy();
    const noCsrf = await decidePost(req('/api/v1/admin/enroll-requests/decide', { method: 'POST', headers: { cookie }, body: { ids: [c.request_id], decision: 'approve' } }));
    expect(noCsrf.status).toBe(403);
    expect((await noCsrf.json()).error).toBe('cross_site_request');
    const putNoCsrf = await settingsPut(req('/api/v1/admin/enroll-settings', { method: 'PUT', headers: { cookie }, body: { auto_approve_cidrs: ['10.0.0.0/8'] } }));
    expect(putNoCsrf.status).toBe(403);
    // 帶了 CSRF 標頭就可以
    const withCsrf = await decidePost(
      req('/api/v1/admin/enroll-requests/decide', { method: 'POST', headers: { cookie, 'x-asa-request': '1', 'sec-fetch-site': 'same-origin' }, body: { ids: [c.request_id], decision: 'reject' } }),
    );
    expect(withCsrf.status).toBe(200);
    const [row] = await db.select().from(enrollmentRequests).where(eq(enrollmentRequests.id, c.request_id));
    expect(row.decidedBy).toBe('admin:session');
  });
});
