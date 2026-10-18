import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GET as adminGet, POST as adminPause, PUT as adminPut } from '@/app/api/v1/admin/dns-protect/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { GET as configGet } from '@/app/api/v1/dns/config/route';
import { POST as heartbeat } from '@/app/api/v1/dns/heartbeat/route';
import { POST as queries } from '@/app/api/v1/dns/queries/route';
import { dnsResolverQueries, dnsServers } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { createApiToken } from '@/lib/auth/tokens';
import type { DB } from '@/lib/db';
import { cleanDomain, listedBy, resolverStats, validUpstream } from '@/lib/dns/protect';
import { resetEnvForTests } from '@/lib/env';
import { createTestDb } from '../helpers/db';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const A = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
const ENV_TOKEN = 'compose-dns-token-0123456789abcdef0123';

let db: DB;
let dnsToken: string;
let readToken: string;

function req(url: string, init: { method?: string; token?: string; body?: unknown; headers?: Record<string, string> } = {}) {
  return new Request(`http://localhost:3000${url}`, {
    method: init.method ?? 'GET',
    headers: {
      'content-type': 'application/json',
      ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
      ...(init.headers ?? {}),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

/** 契約範例改成最近的時間（固定日期會超過保留天數被略過）。 */
function recentBatch() {
  const b = load('dns-resolver.v1.json') as { records: { ts: string }[] };
  b.records = b.records.map((r, i) => ({ ...r, ts: new Date(Date.now() - (5 - i) * 60_000).toISOString() }));
  return b;
}

beforeAll(async () => {
  db = await createTestDb();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  resetEnvForTests();
  const r = await register(req('/api/v1/agents/register', { method: 'POST', token: 'client-a', body: load('register.v1.json') }));
  expect(r.status).toBe(200);
  dnsToken = (await createApiToken({ name: 'office dns', scopes: ['dns'], actor: 'test' })).token;
  readToken = (await createApiToken({ name: 'grafana', scopes: ['read'], actor: 'test' })).token;
});

beforeEach(() => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  delete process.env.ASA_HUB_DNS_TOKEN;
  resetEnvForTests();
  resetRateLimitsForTests();
});

describe('protective DNS: config', () => {
  it('serves the default (forward only) config to a dns token, with ETag/304', async () => {
    const r = await configGet(req('/api/v1/dns/config', { token: dnsToken }));
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body).toMatchObject({ blocking: false, enabled: false, upstreams: [], min_confidence: 75, log: true });
    expect(body.server_id).toMatch(/^token:/);
    const etag = r.headers.get('etag')!;
    expect(etag).toBe(body.etag);
    const again = await configGet(req('/api/v1/dns/config', { token: dnsToken, headers: { 'if-none-match': etag } }));
    expect(again.status).toBe(304);
  });

  it('rejects tokens without the dns scope and anonymous callers', async () => {
    expect((await configGet(req('/api/v1/dns/config', { token: readToken }))).status).toBe(401);
    expect((await configGet(req('/api/v1/dns/config'))).status).toBe(401);
  });

  it('accepts the compose token from AI_SECURITY_MONITOR_HUB_DNS_TOKEN (32+ chars only)', async () => {
    process.env.AI_SECURITY_MONITOR_HUB_DNS_TOKEN = ENV_TOKEN;
    resetEnvForTests();
    const r = await configGet(req('/api/v1/dns/config', { token: ENV_TOKEN }));
    expect(r.status).toBe(200);
    expect((await r.json()).server_id).toBe('env');
    process.env.AI_SECURITY_MONITOR_HUB_DNS_TOKEN = 'short';
    resetEnvForTests();
    expect((await configGet(req('/api/v1/dns/config', { token: 'short' }))).status).toBe(401);
    delete process.env.AI_SECURITY_MONITOR_HUB_DNS_TOKEN;
  });

  it('lets an enrolled agent act as a DNS server with its client key', async () => {
    const r = await configGet(req('/api/v1/dns/config', { token: 'client-a', headers: { 'x-asa-agent-id': A } }));
    expect(r.status).toBe(200);
    expect((await r.json()).server_id).toBe(`agent:${A}`);
    expect((await configGet(req('/api/v1/dns/config', { token: 'client-a', headers: { 'x-asa-agent-id': 'nope' } }))).status).toBe(401);
  });

  it('admin turns blocking on, pauses and resumes; the ETag follows', async () => {
    const before = (await (await configGet(req('/api/v1/dns/config', { token: dnsToken }))).json()).etag;
    const put = await adminPut(
      req('/api/v1/admin/dns-protect', { method: 'PUT', token: 'test-admin', body: { enabled: true, block: ['*.Bad.Example.', 'bad.example'], allow: ['ok.example'] } }),
    );
    expect(put.status).toBe(200);
    expect((await put.json()).settings).toMatchObject({ enabled: true, block: ['bad.example'], allow: ['ok.example'] });
    const on = await (await configGet(req('/api/v1/dns/config', { token: dnsToken }))).json();
    expect(on.blocking).toBe(true);
    expect(on.etag).not.toBe(before);

    const paused = await adminPause(req('/api/v1/admin/dns-protect', { method: 'POST', token: 'test-admin', body: { pause_minutes: 5 } }));
    expect(paused.status).toBe(200);
    const p = await (await configGet(req('/api/v1/dns/config', { token: dnsToken }))).json();
    expect(p.blocking).toBe(false);
    expect(Date.parse(p.paused_until)).toBeGreaterThan(Date.now() + 4 * 60_000);

    await adminPause(req('/api/v1/admin/dns-protect', { method: 'POST', token: 'test-admin', body: { pause_minutes: 0 } }));
    expect((await (await configGet(req('/api/v1/dns/config', { token: dnsToken }))).json()).blocking).toBe(true);
  });

  it('hands out the resolver IPs devices should use', async () => {
    const put = await adminPut(req('/api/v1/admin/dns-protect', { method: 'PUT', token: 'test-admin', body: { resolver_ips: ['192.168.1.5', 'FD00::5', '192.168.1.5'] } }));
    expect(put.status).toBe(200);
    const cfg = await (await configGet(req('/api/v1/dns/config', { token: 'client-a', headers: { 'x-asa-agent-id': A } }))).json();
    expect(cfg.resolver_ips).toEqual(['192.168.1.5', 'fd00::5']);
  });

  it('adds and removes single blocklist / allow list entries without overwriting others', async () => {
    await adminPut(req('/api/v1/admin/dns-protect', { method: 'PUT', token: 'test-admin', body: { block: ['keep.example'], allow: [] } }));
    const add = await adminPause(req('/api/v1/admin/dns-protect', { method: 'POST', token: 'test-admin', body: { block_add: ['https://Phish.Example/login', 'not a domain'] } }));
    expect(add.status).toBe(200);
    const a = await add.json();
    expect(a.settings.block).toEqual(['keep.example', 'phish.example']);
    expect(a.invalid).toEqual(['not a domain']);
    // 加進允許清單會從黑名單拿掉
    const allow = await (await adminPause(req('/api/v1/admin/dns-protect', { method: 'POST', token: 'test-admin', body: { allow_add: ['phish.example'] } }))).json();
    expect(allow.settings.block).toEqual(['keep.example']);
    expect(allow.settings.allow).toEqual(['phish.example']);
    const rm = await (await adminPause(req('/api/v1/admin/dns-protect', { method: 'POST', token: 'test-admin', body: { block_remove: ['keep.example'], allow_remove: ['phish.example'] } }))).json();
    expect(rm.settings).toMatchObject({ block: [], allow: [] });
    expect((await adminPause(req('/api/v1/admin/dns-protect', { method: 'POST', token: 'test-admin', body: { block_add: 'x' } }))).status).toBe(400);
    expect(cleanDomain('*.Bad.Example.')).toBe('bad.example');
    expect(listedBy(['bad.example'], 'a.b.bad.example')).toBe('bad.example');
    expect(listedBy(['bad.example'], 'example')).toBeNull();
  });

  it('validates settings', async () => {
    for (const body of [{ upstreams: ['ftp://x'] }, { block: ['not a domain'] }, { min_confidence: 5 }, { enabled: 'yes' }, { resolver_ips: ['lan'] }]) {
      const r = await adminPut(req('/api/v1/admin/dns-protect', { method: 'PUT', token: 'test-admin', body }));
      expect(r.status, JSON.stringify(body)).toBe(400);
    }
    expect((await adminPut(req('/api/v1/admin/dns-protect', { method: 'PUT', token: dnsToken, body: { enabled: false } }))).status).toBe(401);
    expect(validUpstream('https://dns.quad9.net/dns-query')).toBe(true);
    expect(validUpstream('9.9.9.9')).toBe(true);
    expect(validUpstream('9.9.9.9:5353')).toBe(true);
    expect(validUpstream('[2620:fe::fe]:53')).toBe(true);
    expect(validUpstream('http://dns.example/dns-query')).toBe(false);
  });
});

describe('protective DNS: heartbeat and query log', () => {
  it('stores the heartbeat (contract sample) and returns the config ETag', async () => {
    const r = await heartbeat(req('/api/v1/dns/heartbeat', { method: 'POST', token: dnsToken, body: load('dns-heartbeat.v1.json') }));
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.config_etag).toMatch(/^"/);
    const [row] = await db.select().from(dnsServers).where(eq(dnsServers.id, body.server_id));
    expect(row).toMatchObject({ name: 'office dns', hostname: 'dns-01', version: '0.6.0' });
    expect((row!.status as { blocklist_entries: number }).blocklist_entries).toBe(354812);
  });

  it('stores resolver records (contract sample), maps clients to hosts and counts blocks', async () => {
    const r = await queries(req('/api/v1/dns/queries', { method: 'POST', token: dnsToken, body: recentBatch() }));
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true, stored: 3, mapped: 1 });
    // 重送同一批：覆蓋、不重複
    await queries(req('/api/v1/dns/queries', { method: 'POST', token: dnsToken, body: recentBatch() }));
    const rows = await db.select().from(dnsResolverQueries);
    expect(rows.length).toBeGreaterThanOrEqual(3);
    const blocked = rows.find((x) => x.rcode === 'BLOCKED')!;
    expect(blocked).toMatchObject({ blockedBy: 'CERT Polska', client: '192.0.2.77', agentId: null });
    expect(rows.find((x) => x.client === '192.0.2.10')!.agentId).toBe(A);
    const s = await resolverStats(db);
    expect(s.blocked).toBeGreaterThanOrEqual(3);
    expect(s.topBlocked[0]).toMatchObject({ registrable: 'example-phish.test', by: 'CERT Polska' });
    expect(s.topClients.find((c) => c.client === '192.0.2.10')?.hostname).toBeTruthy();
  });

  it('rejects malformed batches and unknown callers', async () => {
    const bad = recentBatch() as { records: Record<string, unknown>[] };
    bad.records[0]!.client = 'not-an-ip';
    expect((await queries(req('/api/v1/dns/queries', { method: 'POST', token: dnsToken, body: bad }))).status).toBe(400);
    expect((await queries(req('/api/v1/dns/queries', { method: 'POST', token: readToken, body: recentBatch() }))).status).toBe(401);
  });

  it('admin view lists servers, stats and domain feed options', async () => {
    const r = await adminGet(req('/api/v1/admin/dns-protect', { token: 'test-admin' }));
    expect(r.status).toBe(200);
    const v = await r.json();
    expect(v.servers.some((s: { name: string; online: boolean }) => s.name === 'office dns' && s.online)).toBe(true);
    expect(v.stats.queries).toBeGreaterThan(0);
    expect(v.defaultUpstreams.length).toBe(2);
    expect(Array.isArray(v.feeds)).toBe(true);
    expect((await adminGet(req('/api/v1/admin/dns-protect', { token: dnsToken }))).status).toBe(403);
  });
});
