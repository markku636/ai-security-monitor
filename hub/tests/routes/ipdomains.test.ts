// IP 上的網域：快照 dns_names 寫入 ip_domains、被動 DNS 來源（HackerTarget／VirusTotal／OTX）解析與查詢、
// /api/v1/ip-intel/domains 權限與稽核、批次查詢不會用到這些來源、排名與清除歷史。
import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { GET as domainsGet, POST as domainsPost } from '@/app/api/v1/ip-intel/domains/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { POST as snapshot } from '@/app/api/v1/ingest/snapshot/route';
import { auditLog, ipDomainLookups, ipDomains, ipReputation, settings } from '@/drizzle/schema';
import { clearConnectionHistory, clearIpIntelCache } from '@/lib/history';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { resetThrottleForTests } from '@/lib/ingest/route';
import {
  getIpDomainsView,
  localDomainMap,
  lookupDomains,
  normalizeDomain,
  parseHackertarget,
  parseOtx,
  parseVirustotal,
  pruneLocalDomains,
} from '@/lib/ipintel/domains';
import { lookupIp } from '@/lib/ipintel/service';
import type { IpDomainsView } from '@/lib/ipintel/types';
import { riskyIpRanking } from '@/lib/queries/connections';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const admin = { authorization: 'Bearer test-admin' };
const AGENT = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';

const WEB = '93.184.216.34';
const CDN = '151.101.1.69';
/** 快照裡沒有這個 IP 的連線（dns_names 帶了也不收）。 */
const STRAY = '8.8.4.4';

function clientPost(pathname: string, body: unknown) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer client-a' },
    body: JSON.stringify(body),
  });
}

function snap(dnsNames?: Record<string, string[]>) {
  const s = load('snapshot.v1.json');
  const base = s.connections[0];
  s.ts = new Date().toISOString();
  s.connections = [WEB, CDN].map((ip, i) => {
    const c = structuredClone(base);
    c.remote_ip = ip;
    c.remote_port = 443 + i;
    c.verdict = { level: 'suspicious', reasons: [{ type: 'anomaly', kind: 'temp_dir_process', detail: 'x' }] };
    return c;
  });
  if (dnsNames) s.dns_names = dnsNames;
  else delete s.dns_names;
  return s;
}

/** 被動 DNS 三個來源的假回應；記下打了哪些網址。 */
function fakeFetch(opts: { htQuota?: boolean } = {}) {
  const calls: string[] = [];
  const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    calls.push(u);
    if (u.startsWith('https://api.hackertarget.com/')) {
      return new Response(opts.htQuota ? 'API count exceeded - Increase Quota with Membership' : 'www.example.com\nexample.com\nnot a domain\n', { status: 200 });
    }
    if (u.startsWith('https://www.virustotal.com/')) {
      expect((init?.headers as Record<string, string>)['x-apikey']).toBe('vt-key-123456');
      return Response.json({
        data: [
          { attributes: { host_name: 'WWW.Example.com.', date: 1_790_000_000 } },
          { attributes: { host_name: 'old.example.net', date: 1_600_000_000 } },
        ],
        meta: { count: 1234 },
      });
    }
    if (u.startsWith('https://otx.alienvault.com/')) {
      return Response.json({
        passive_dns: [
          { hostname: 'api.example.org', record_type: 'A', last: '2026-10-01T00:00:00' },
          { hostname: 'mail.example.org', record_type: 'MX', last: '2026-10-01T00:00:00' },
        ],
        count: 2,
      });
    }
    return new Response('not found', { status: 404 });
  });
  return { f, calls };
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
  process.env.ASA_HUB_SNAPSHOT_MIN_INTERVAL_MS = '0';
  resetEnvForTests();
  await register(clientPost('/api/v1/agents/register', load('register.v1.json')));
});

beforeEach(async () => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  delete process.env.ASA_HUB_IP_LOOKUPS;
  delete process.env.ASA_HUB_VIRUSTOTAL_KEY;
  resetEnvForTests();
  resetRateLimitsForTests();
  resetThrottleForTests();
  await db.delete(ipDomainLookups);
  await db.delete(ipReputation);
  await db.delete(settings);
  await db.insert(settings).values({ key: 'ipintel.config', value: { keys: {}, disabled: ['rdns'] }, updatedBy: 'test' });
  await db.delete(auditLog);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('parsers', () => {
  it('normalizes domain names and rejects junk', () => {
    expect(normalizeDomain('WWW.Example.COM.')).toBe('www.example.com');
    expect(normalizeDomain('localhost')).toBeNull();
    expect(normalizeDomain('4.3.2.1.in-addr.arpa')).toBeNull();
    expect(normalizeDomain('bad name.com')).toBeNull();
    expect(normalizeDomain(42)).toBeNull();
  });

  it('parses HackerTarget text, empty answers, quota and errors', () => {
    expect(parseHackertarget('a.example.com\r\nb.example.com\nb.example.com\n')).toEqual({
      ok: true,
      list: { total: 2, items: [{ name: 'a.example.com', lastSeen: null }, { name: 'b.example.com', lastSeen: null }] },
    });
    expect(parseHackertarget('No DNS A records found for 1.2.3.4')).toEqual({ ok: true, list: { total: 0, items: [] } });
    expect(parseHackertarget('API count exceeded - Increase Quota with Membership')).toMatchObject({ ok: false, reason: 'quota-exhausted' });
    expect(parseHackertarget('error check your search parameter')).toMatchObject({ ok: false, reason: 'http-error' });
  });

  it('parses VirusTotal resolutions and OTX passive DNS (A/AAAA only), newest first', () => {
    const vt = parseVirustotal({
      data: [{ attributes: { host_name: 'old.example.com', date: 1_600_000_000 } }, { attributes: { host_name: 'new.example.com', date: 1_700_000_000 } }],
      meta: { count: 99 },
    })!;
    expect(vt.total).toBe(99);
    expect(vt.items.map((x) => x.name)).toEqual(['new.example.com', 'old.example.com']);
    expect(vt.items[0].lastSeen).toBe(new Date(1_700_000_000_000).toISOString());
    expect(parseVirustotal({ error: 'x' })).toBeNull();

    const otx = parseOtx({
      passive_dns: [
        { hostname: 'a.example.org', record_type: 'A', last: '2026-01-02T03:04:05' },
        { hostname: 'a.example.org', record_type: 'A', last: '2026-05-02T03:04:05' },
        { hostname: 'mx.example.org', record_type: 'MX', last: '2026-05-02T03:04:05' },
      ],
    })!;
    expect(otx.items).toEqual([{ name: 'a.example.org', lastSeen: '2026-05-02T03:04:05.000Z' }]);
    expect(parseOtx({})).toBeNull();
  });
});

describe('domains reported by hosts (snapshot dns_names)', () => {
  it('stores names only for IPs the snapshot actually connects to, keeps the newest, prunes after 30 days', async () => {
    const r = await snapshot(
      clientPost(
        '/api/v1/ingest/snapshot',
        snap({ [WEB]: ['www.example.com', 'WWW.EXAMPLE.COM.', 'not a domain', 'localhost'], [CDN]: ['cdn.example.net'], [STRAY]: ['dns.google'] }),
      ),
    );
    expect(r.status).toBe(200);
    const rows = await db.select().from(ipDomains).where(eq(ipDomains.agentId, AGENT));
    expect(rows.map((x) => `${x.ip} ${x.domain}`).sort()).toEqual([`${CDN} cdn.example.net`, `${WEB} www.example.com`]);

    // 舊版 agent 不送 dns_names：照收
    expect((await snapshot(clientPost('/api/v1/ingest/snapshot', snap()))).status).toBe(200);
    // 太多名稱的單一 IP 會被擋
    expect((await snapshot(clientPost('/api/v1/ingest/snapshot', snap({ [WEB]: Array.from({ length: 21 }, (_, i) => `h${i}.example.com`) })))).status).toBe(400);

    expect(await localDomainMap([WEB, CDN, STRAY])).toEqual(new Map([[WEB, 'www.example.com'], [CDN, 'cdn.example.net']]));
    const view = await getIpDomainsView(WEB);
    expect(view.local).toEqual([{ domain: 'www.example.com', hosts: ['demo-host'], lastSeenAt: expect.any(String) }]);

    // 排名的 IP 底下顯示代表網域
    const ranking = await riskyIpRanking(10, undefined, undefined, 'all');
    expect(ranking.items.find((x) => x.remoteIp === WEB)?.domain).toBe('www.example.com');

    await db.update(ipDomains).set({ lastSeenAt: new Date(Date.now() - 31 * 86_400_000) }).where(eq(ipDomains.ip, CDN));
    expect(await pruneLocalDomains(db)).toBe(1);
    expect(await localDomainMap([CDN])).toEqual(new Map());
  });
});

describe('external passive DNS lookups', () => {
  it('queries enabled sources, merges results, caches, and respects quota answers', async () => {
    process.env.ASA_HUB_VIRUSTOTAL_KEY = 'vt-key-123456';
    resetEnvForTests();
    const { f, calls } = fakeFetch();
    const { view, queried } = await lookupDomains(WEB, { actor: 'admin', fetch: f });
    expect(queried.sort()).toEqual(['hackertarget', 'otx', 'virustotal']);
    expect(calls.some((u) => u.includes('reverseiplookup/?q=93.184.216.34'))).toBe(true);
    expect(calls.some((u) => u.includes('/indicators/IPv4/93.184.216.34/passive_dns'))).toBe(true);
    // www.example.com 兩個來源都有 → 排在最前面；VT 報的總數 1234
    expect(view.merged[0]).toMatchObject({ name: 'www.example.com', sources: expect.arrayContaining(['hackertarget', 'virustotal']) });
    expect(view.merged.map((x) => x.name)).toEqual(expect.arrayContaining(['example.com', 'old.example.net', 'api.example.org']));
    expect(view.merged.map((x) => x.name)).not.toContain('mail.example.org');
    expect(view.total).toBe(1234);
    expect(view.providers.find((p) => p.id === 'virustotal')?.hit).toBe(true);

    // 快取內不重打
    const again = await lookupDomains(WEB, { actor: 'admin', fetch: f });
    expect(again.queried).toEqual([]);
    // 「查過網域」不等於「查過外部情資」：ip_reputation 沒有被寫
    expect(await db.select().from(ipReputation)).toEqual([]);

    // 額度用完的回應：標示原因
    const q = fakeFetch({ htQuota: true });
    const r = await lookupDomains(CDN, { actor: 'admin', fetch: q.f });
    expect(r.view.providers.find((p) => p.id === 'hackertarget')?.result).toMatchObject({ ok: false, reason: 'quota-exhausted' });
  });

  it('skips VirusTotal without a key, disabled sources, and private IPs', async () => {
    await db.update(settings).set({ value: { keys: {}, disabled: ['rdns', 'otx'] } }).where(eq(settings.key, 'ipintel.config'));
    const { f, calls } = fakeFetch();
    const { queried, view } = await lookupDomains(WEB, { actor: 'admin', fetch: f });
    expect(queried).toEqual(['hackertarget']);
    expect(calls.every((u) => u.startsWith('https://api.hackertarget.com/'))).toBe(true);
    expect(view.providers.find((p) => p.id === 'virustotal')).toMatchObject({ configured: false, willQuery: false });
    await expect(lookupDomains('10.0.0.5', { actor: 'admin', fetch: f })).rejects.toThrow();
  });

  it('batch / reputation lookups never call the passive DNS sources', async () => {
    const { f, calls } = fakeFetch();
    await lookupIp(WEB, { actor: 'admin', deps: { fetch: f } });
    expect(calls.filter((u) => /hackertarget|virustotal|otx\.alienvault/.test(u))).toEqual([]);
  });
});

describe('/api/v1/ip-intel/domains', () => {
  it('GET reads the cache only; POST needs admin, validates, audits the lookup', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    expect((await domainsGet(req(`/api/v1/ip-intel/domains?ip=${WEB}`, { headers: { authorization: 'Bearer client-a' } }))).status).toBe(401);
    const g = await domainsGet(req(`/api/v1/ip-intel/domains?ip=${WEB}`, { headers: admin }));
    expect(g.status).toBe(200);
    expect(((await g.json()) as IpDomainsView).queriedAt).toBeNull();
    expect(calls).toHaveLength(0);
    expect((await domainsGet(req('/api/v1/ip-intel/domains?ip=nope', { headers: admin }))).status).toBe(400);

    expect((await domainsPost(req('/api/v1/ip-intel/domains', { method: 'POST', body: { ip: WEB } }))).status).toBe(401);
    expect((await domainsPost(req('/api/v1/ip-intel/domains', { method: 'POST', body: { ip: '10.1.1.1' }, headers: admin }))).status).toBe(400);
    const p = await domainsPost(req('/api/v1/ip-intel/domains', { method: 'POST', body: { ip: WEB }, headers: admin }));
    expect(p.status).toBe(200);
    expect(((await p.json()) as { queried: string[] }).queried).toContain('hackertarget');
    const audits = await db.select().from(auditLog).where(eq(auditLog.action, 'ip_intel.domains'));
    expect(audits).toHaveLength(1);
    expect(audits[0].targetId).toBe(WEB);

    process.env.ASA_HUB_IP_LOOKUPS = 'off';
    resetEnvForTests();
    expect((await domainsPost(req('/api/v1/ip-intel/domains', { method: 'POST', body: { ip: CDN }, headers: admin }))).status).toBe(409);
  });

  it('clearing history removes host-reported names and cached lookups', async () => {
    const { f } = fakeFetch();
    await lookupDomains(WEB, { actor: 'admin', fetch: f });
    expect((await snapshot(clientPost('/api/v1/ingest/snapshot', snap({ [WEB]: ['www.example.com'] })))).status).toBe(200);
    await clearIpIntelCache(db);
    expect(await db.select().from(ipDomainLookups)).toEqual([]);
    await clearConnectionHistory(db, { agentId: AGENT });
    expect(await db.select().from(ipDomains)).toEqual([]);
  });
});
