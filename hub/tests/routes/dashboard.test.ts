import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GET as agentRoute } from '@/app/api/v1/agents/[id]/route';
import { GET as attackersRoute } from '@/app/api/v1/connections/inbound-attackers/route';
import { GET as connectionsRoute } from '@/app/api/v1/connections/route';
import { GET as findingsGet, POST as findingsPost } from '@/app/api/v1/findings/route';
import { GET as fleetRoute } from '@/app/api/v1/fleet/summary/route';
import { GET as feedsRoute } from '@/app/api/v1/intel/feeds/route';
import { GET as lookupRoute } from '@/app/api/v1/intel/lookup/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { POST as report } from '@/app/api/v1/ingest/report/route';
import { POST as snapshot } from '@/app/api/v1/ingest/snapshot/route';
import { agents, auditLog, destinations, findings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { resetThrottleForTests } from '@/lib/ingest/route';
import {
  inboundAttackers,
  listConnections,
  parseConnectionFilter,
  parseRankSort,
  parseRankWindow,
  riskyIpRanking,
  type RankSortKey,
} from '@/lib/queries/connections';
import { listFindings, parseFindingFilter } from '@/lib/queries/findings';
import { topIndicators, topIntelFeeds } from '@/lib/queries/intel';
import { toQuery } from '@/lib/queries/params';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const AGENT = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';

function clientPost(pathname: string, body: unknown) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer client-a' },
    body: JSON.stringify(body),
  });
}

const admin = { authorization: 'Bearer test-admin' };

let db: DB;
/** beforeAll 回報的完整快照（排名測試再送一次，資料不變只累加次數）。 */
let fullSnap: Record<string, unknown>;

beforeAll(async () => {
  db = await createTestDb();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
  process.env.ASA_HUB_SNAPSHOT_MIN_INTERVAL_MS = '0';
  resetEnvForTests();
  await register(clientPost('/api/v1/agents/register', load('register.v1.json')));
  const rep = load('report.v1.json');
  rep.finished_at = new Date().toISOString();
  expect((await report(clientPost('/api/v1/ingest/report', rep))).status).toBe(200);
  // 快照：契約裡的危險對外連線＋一條被情資列名的對內連線＋一條安全連線。
  const snap = load('snapshot.v1.json');
  const inbound = structuredClone(snap.connections[0]);
  inbound.direction = 'inbound';
  inbound.remote_ip = '198.51.100.23';
  inbound.remote_port = 50123;
  inbound.local_port = 3389;
  inbound.process = { pid: 1200, name: 'svchost.exe' };
  inbound.verdict.reasons[1].feed_id = 'blocklist-de-all';
  inbound.verdict.reasons[1].vendor = 'blocklist.de';
  inbound.verdict.reasons = [inbound.verdict.reasons[1]];
  const safe = structuredClone(snap.connections[0]);
  safe.remote_ip = '1.1.1.1';
  safe.remote_port = 443;
  safe.process = { pid: 77, name: 'chrome.exe' };
  safe.geo = { country: 'AU', asn: 13335, org: 'Cloudflare' };
  safe.verdict = { level: 'safe', reasons: [{ type: 'known_good', list: 'public-dns', detail: 'Cloudflare DNS' }] };
  snap.connections.push(inbound, safe);
  fullSnap = structuredClone(snap);
  expect((await snapshot(clientPost('/api/v1/ingest/snapshot', snap))).status).toBe(200);
});

beforeEach(() => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  delete process.env.ASA_HUB_PUBLIC_DASHBOARD;
  resetEnvForTests();
  resetThrottleForTests();
  resetRateLimitsForTests();
});

describe('query params', () => {
  it('parses and ignores unknown values', () => {
    const f = parseConnectionFilter(new URLSearchParams('verdict=dangerous,bogus&direction=inbound&limit=9999&country=nl'));
    expect(f.verdict).toEqual(['dangerous']);
    expect(f.direction).toEqual(['inbound']);
    expect(f.limit).toBe(200);
    expect(f.country).toBe('NL');
    expect(parseFindingFilter({}).status).toEqual(['open', 'acked']);
    expect(toQuery({ a: ['x', 'y'], b: undefined, c: 0, d: '' })).toBe('?a=x%2Cy&c=0');
  });
});

describe('connection queries', () => {
  it('filters by verdict, direction, feed and keyword with facets', async () => {
    const all = await listConnections(parseConnectionFilter({}));
    expect(all.total).toBe(3);
    expect(all.items[0].verdict).toBe('dangerous');
    expect(all.facets.verdict).toMatchObject({ dangerous: 2, safe: 1 });

    const bad = await listConnections(parseConnectionFilter({ verdict: 'dangerous', direction: 'inbound' }));
    expect(bad.items.map((c) => c.remoteIp)).toEqual(['198.51.100.23']);
    // facets 不受自己那一維的篩選影響
    expect(bad.facets.direction).toMatchObject({ inbound: 1, outbound: 1 });

    const feed = await listConnections(parseConnectionFilter({ feed: 'abusech-feodo' }));
    expect(feed.items.map((c) => c.remoteIp)).toEqual(['203.0.113.66']);
    const kw = await listConnections(parseConnectionFilter({ q: 'chrome' }));
    expect(kw.items.map((c) => c.processName)).toEqual(['chrome.exe']);
    const reasons = feed.items[0].reasons;
    expect(reasons.find((r) => r.type === 'intel_hit')?.source_url).toContain('feodotracker');
  });

  it('filters by protocol, state, reason kind, process, port and public IPs; sorts by any column', async () => {
    const q = async (p: Record<string, string>) => (await listConnections(parseConnectionFilter(p))).items.map((c) => c.remoteIp);
    const all = await listConnections(parseConnectionFilter({}));
    expect(all.facets.proto).toEqual({ tcp: 3 });
    expect(all.facets.state).toEqual({ ESTABLISHED: 3 });
    expect(all.facets.reason).toEqual({ intel: 2, none: 1 });
    expect(all.facets.process.map((p) => p.name).sort()).toEqual(['chrome.exe', 'svchost.exe', 'updater.exe']);

    expect((await q({ reason: 'none' }))).toEqual(['1.1.1.1']);
    expect((await q({ reason: 'intel' })).sort()).toEqual(['198.51.100.23', '203.0.113.66']);
    expect(await q({ proto: 'udp' })).toEqual([]);
    expect((await q({ state: 'established' })).length).toBe(3);
    expect(await q({ process: 'chrome.exe' })).toEqual(['1.1.1.1']);
    expect(await q({ port: '3389' })).toEqual(['198.51.100.23']);
    expect((await q({ public: '1' })).length).toBe(3);

    expect(await q({ sort: 'remote', dir: 'asc' })).toEqual(['1.1.1.1', '198.51.100.23', '203.0.113.66']);
    expect(await q({ sort: 'remote', dir: 'desc' })).toEqual(['203.0.113.66', '198.51.100.23', '1.1.1.1']);
    expect(await q({ sort: 'process' })).toEqual(['1.1.1.1', '198.51.100.23', '203.0.113.66']);

    const f = parseConnectionFilter({ port: 'abc', sort: 'bogus', state: 'ESTABLISHED,drop table,TIME_WAIT', public: 'yes' });
    expect(f).toMatchObject({ port: undefined, sort: undefined, state: ['ESTABLISHED', 'TIME_WAIT'], publicOnly: false });
  });

  it('aggregates inbound attackers with their feeds', async () => {
    const a = await inboundAttackers();
    expect(a).toHaveLength(1);
    expect(a[0]).toMatchObject({ remoteIp: '198.51.100.23', worst: 'dangerous', hosts: 1, conns: 1 });
    expect(a[0].feeds).toEqual(['blocklist-de-all']);
    expect(a[0].ports).toEqual([3389]);
  });

  it('ranks risky remote IPs by severity and times seen, with live counts', async () => {
    // 同一份快照再回報一次：每個可疑／危險目的地的累計次數 +1，安全的 1.1.1.1 不進排名
    const again = { ...structuredClone(fullSnap), ts: new Date().toISOString() };
    expect((await snapshot(clientPost('/api/v1/ingest/snapshot', again))).status).toBe(200);

    const r = await riskyIpRanking(10);
    expect(r.items.map((x) => x.remoteIp)).not.toContain('1.1.1.1');
    expect(r.total).toBe(r.items.length);
    expect(r.items.map((x) => x.rank)).toEqual(r.items.map((_, i) => i + 1));
    expect(r.items.find((x) => x.remoteIp === '203.0.113.66')).toMatchObject({
      worst: 'dangerous',
      seen: 2,
      live: 1,
      hosts: 1,
      directions: ['outbound'],
    });
    expect(r.items.find((x) => x.remoteIp === '198.51.100.23')).toMatchObject({
      worst: 'dangerous',
      seen: 2,
      live: 1,
      ports: [50123],
      directions: ['inbound'],
      processes: ['svchost.exe'],
    });

    expect((await riskyIpRanking(10, 'no-such-agent')).items).toEqual([]);
  });

  it('records when a destination was last risky and filters the ranking by time window', async () => {
    const rows = await db.select().from(destinations);
    const risky = rows.filter((r) => r.worstVerdict === 'dangerous' || r.worstVerdict === 'suspicious');
    expect(risky.length).toBeGreaterThan(0);
    expect(risky.every((r) => r.lastRiskyAt instanceof Date)).toBe(true);
    expect(rows.filter((r) => r.worstVerdict === 'safe').every((r) => r.lastRiskyAt === null)).toBe(true);

    expect(parseRankWindow({})).toBe('30');
    expect(parseRankWindow({ rwin: '7' })).toBe('7');
    expect(parseRankWindow({ rwin: 'forever' })).toBe('30');

    // 對內那個 IP 最後一次被判可疑是 60 天前：30 天內不列，全部時間才列
    await db
      .update(destinations)
      .set({ lastRiskyAt: new Date(Date.now() - 60 * 86_400_000) })
      .where(eq(destinations.remoteIp, '198.51.100.23'));
    const ips = async (w: '7' | '30' | 'all') =>
      (await riskyIpRanking(10, undefined, undefined, w)).items.map((x) => x.remoteIp).sort();
    expect(await ips('all')).toEqual(['198.51.100.23', '203.0.113.66']);
    expect(await ips('30')).toEqual(['203.0.113.66']);
    expect((await riskyIpRanking(10, undefined, undefined, '30')).total).toBe(1);
    await db.update(destinations).set({ lastRiskyAt: new Date() }).where(eq(destinations.remoteIp, '198.51.100.23'));
  });

  it('sorts the ranking by any column and parses rsort/rdir', async () => {
    expect(parseRankSort({})).toEqual({ key: 'verdict', dir: 'desc' });
    expect(parseRankSort({ rsort: 'ip' })).toEqual({ key: 'ip', dir: 'asc' });
    expect(parseRankSort({ rsort: 'seen', rdir: 'asc' })).toEqual({ key: 'seen', dir: 'asc' });
    expect(parseRankSort({ rsort: 'bogus', rdir: 'sideways' })).toEqual({ key: 'verdict', dir: 'desc' });

    const ips = async (key: RankSortKey, dir: 'asc' | 'desc') => (await riskyIpRanking(10, undefined, { key, dir })).items.map((x) => x.remoteIp);
    // IP 依位址數值排序，不是字串（198 < 203）
    expect(await ips('ip', 'asc')).toEqual(['198.51.100.23', '203.0.113.66']);
    expect(await ips('ip', 'desc')).toEqual(['203.0.113.66', '198.51.100.23']);
    // 方向／port：對內那筆打的是 50123，對外是契約裡的 443
    expect(await ips('port', 'asc')).toEqual(['203.0.113.66', '198.51.100.23']);
    // 名次跟著目前的排序走
    expect((await riskyIpRanking(10, undefined, { key: 'ip', dir: 'desc' })).items.map((x) => x.rank)).toEqual([1, 2]);
  });

  it('summarises intel hits by feed and indicator with sources', async () => {
    const feeds = await topIntelFeeds(7);
    expect(feeds[0]).toMatchObject({ feedId: 'abusech-feodo', vendor: 'abuse.ch', indicators: 1, hosts: 1 });
    const ind = await topIndicators(7);
    expect(ind[0].indicator).toBe('203.0.113.66');
    expect(ind[0].sources[0].source_url).toContain('feodotracker');
  });
});

describe('dashboard API', () => {
  it('requires admin for connection details; viewers only get the fleet summary', async () => {
    expect((await connectionsRoute(req('/api/v1/connections', { headers: admin }))).status).toBe(200);
    expect((await connectionsRoute(req('/api/v1/connections', { headers: { authorization: 'Bearer client-a' } }))).status).toBe(401);
    process.env.ASA_HUB_PUBLIC_DASHBOARD = '1';
    resetEnvForTests();
    expect((await connectionsRoute(req('/api/v1/connections'))).status).toBe(401);
    expect((await attackersRoute(req('/api/v1/connections/inbound-attackers'))).status).toBe(401);
    const fleet = await fleetRoute(req('/api/v1/fleet/summary'));
    expect(fleet.status).toBe(200);
    const body = await fleet.json();
    expect(body.agents.total).toBe(1);
    expect(body.score.overall).toBe(52);
    expect(body.intel_feeds[0].source_url).toContain('feodotracker');
  });

  it('serves agent detail and 404s for unknown agents', async () => {
    const ok = await agentRoute(req(`/api/v1/agents/${AGENT}`, { headers: admin }), { params: Promise.resolve({ id: AGENT }) });
    expect(ok.status).toBe(200);
    expect((await ok.json()).reports).toHaveLength(1);
    const nope = await agentRoute(req('/api/v1/agents/ghost', { headers: admin }), { params: Promise.resolve({ id: 'ghost' }) });
    expect(nope.status).toBe(404);
  });

  it('bulk ack / reopen / suppress updates counts and writes audit', async () => {
    const list = await (await findingsGet(req('/api/v1/findings?severity=critical', { headers: admin }))).json();
    expect(list.total).toBe(2);
    const key = { agent_id: AGENT, finding_id: list.items[0].findingId };

    const ack = await findingsPost(req('/api/v1/findings', { method: 'POST', headers: admin, body: { action: 'ack', keys: [key] }, sameSite: false }));
    expect(ack.status).toBe(200);
    expect((await ack.json()).changed).toBe(1);
    let a = (await db.select().from(agents).where(eq(agents.id, AGENT)))[0];
    expect(a.openFindings).toBe(1);
    expect(a.sevCounts.critical).toBe(1);
    // 已確認的不能再確認
    const again = await (await findingsPost(req('/api/v1/findings', { method: 'POST', headers: admin, body: { action: 'ack', keys: [key] } }))).json();
    expect(again.changed).toBe(0);

    await findingsPost(req('/api/v1/findings', { method: 'POST', headers: admin, body: { action: 'reopen', keys: [key] } }));
    a = (await db.select().from(agents).where(eq(agents.id, AGENT)))[0];
    expect(a.openFindings).toBe(2);

    const sup = await findingsPost(
      req('/api/v1/findings', { method: 'POST', headers: admin, body: { action: 'suppress', keys: [key], days: 7, reason: 'lab box' } }),
    );
    expect((await sup.json()).changed).toBe(1);
    const row = (await db.select().from(findings).where(eq(findings.findingId, key.finding_id)))[0];
    expect(row.status).toBe('suppressed');
    expect(row.suppressReason).toBe('lab box');
    expect(row.suppressedUntil!.getTime()).toBeGreaterThan(Date.now() + 6 * 86_400_000);

    const open = await listFindings(parseFindingFilter({ agent_id: AGENT }));
    expect(open.facets.status).toMatchObject({ open: 1, suppressed: 1 });

    const logs = await db.select().from(auditLog).where(eq(auditLog.action, 'findings.suppress'));
    expect(logs).toHaveLength(1);
    expect(logs[0].details).toMatchObject({ changed: 1, reason: 'lab box' });
  });

  it('rejects cross-site writes from cookie identities and bad bodies', async () => {
    delete process.env.ASA_HUB_ADMIN_SECRET;
    delete process.env.ASA_HUB_CLIENT_SECRETS;
    resetEnvForTests();
    // 開放模式（等同 cookie 身分）：沒有 X-ASA-Request → 403
    const csrf = await findingsPost(
      req('/api/v1/findings', { method: 'POST', body: { action: 'ack', keys: [{ agent_id: AGENT, finding_id: 'x' }] }, sameSite: false }),
    );
    expect(csrf.status).toBe(403);
    const bad = await findingsPost(req('/api/v1/findings', { method: 'POST', body: { action: 'delete', keys: [] } }));
    expect(bad.status).toBe(400);
    const tooMany = await findingsPost(
      req('/api/v1/findings', {
        method: 'POST',
        body: { action: 'ack', keys: Array.from({ length: 501 }, (_, i) => ({ agent_id: AGENT, finding_id: `f${i}` })) },
      }),
    );
    expect(tooMany.status).toBe(400);
  });
});

describe('intel API', () => {
  it('lists the feed registry with 7-day hit stats (viewers allowed)', async () => {
    process.env.ASA_HUB_PUBLIC_DASHBOARD = '1';
    resetEnvForTests();
    const r = await (await feedsRoute(req('/api/v1/intel/feeds'))).json();
    const feodo = r.items.find((f: { id: string }) => f.id === 'abusech-feodo');
    expect(feodo.license.commercial_ok).toBe(true);
    expect(feodo.hits_7d).toMatchObject({ indicators: 1, hosts: 1 });
    const dshield = r.items.find((f: { id: string }) => f.id === 'dshield-block');
    expect(dshield.license.commercial_ok).toBe(false);
    expect(r.items.length).toBeGreaterThan(20);
  });

  it('looks up an indicator across hits, connections and history', async () => {
    const r = await (await lookupRoute(req('/api/v1/intel/lookup?q=203.0.113.66', { headers: admin }))).json();
    expect(r.hits[0]).toMatchObject({ vendor: 'abuse.ch', confidence: 90 });
    expect(r.connections[0]).toMatchObject({ verdict: 'dangerous', direction: 'outbound', processName: 'updater.exe' });
    expect(r.destinations[0].worstVerdict).toBe('dangerous');
    expect((await lookupRoute(req('/api/v1/intel/lookup', { headers: admin }))).status).toBe(400);
    expect((await lookupRoute(req('/api/v1/intel/lookup?q=1.1.1.1'))).status).toBe(401);
  });
});
