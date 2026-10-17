// 批次 IP 分析：/api/v1/ip-intel/batch、快取風險（IP 旁圖示）、排名「外部風險」欄與排序、AI 一次分析多個 IP。
import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { POST as streamRoute } from '@/app/api/ai/stream/route';
import { POST as login } from '@/app/api/auth/login/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { POST as batchPost } from '@/app/api/v1/ip-intel/batch/route';
import { POST as snapshot } from '@/app/api/v1/ingest/snapshot/route';
import { aiAnalyses, auditLog, ipNotes, ipReputation, settings } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { BATCH_MAX, cachedRiskMap, lookupBatch, lookupIp } from '@/lib/ipintel/service';
import type { BatchLookupItem, IpRisk } from '@/lib/ipintel/types';
import { riskyIpRanking } from '@/lib/queries/connections';
import { createTestDb } from '../helpers/db';
import { cookieFrom, req } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const FAKE = path.resolve(__dirname, '../fixtures/fake-claude.mjs');
const admin = { authorization: 'Bearer test-admin' };

/** 排名裡的 IP：BAD 會查出高分、MEH 低分、NEW 從沒查過、LAN 是內網。 */
const BAD = '45.155.205.233';
const MEH = '185.199.108.153';
const NEW = '93.184.216.34';
const LAN = '10.20.30.40';
/** 這個 IP 的所有外部來源都會連線失敗。 */
const FLAKY = '91.92.93.94';

function clientPost(pathname: string, body: unknown) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer client-a' },
    body: JSON.stringify(body),
  });
}

/** 依 URL 裡的 IP 回不同的分數；FLAKY 一律連不上。 */
function fakeFetch() {
  const calls: string[] = [];
  const f = vi.fn(async (url: string | URL | Request) => {
    const u = String(url);
    calls.push(u);
    if (u.includes(FLAKY)) throw new TypeError('fetch failed');
    const ip = [BAD, MEH, NEW].find((x) => u.includes(x)) ?? '0.0.0.0';
    if (u.startsWith('https://api.abuseipdb.com/')) {
      return Response.json({ data: { ipAddress: ip, abuseConfidenceScore: ip === BAD ? 100 : 0, totalReports: ip === BAD ? 812 : 0, countryCode: 'NL', usageType: 'Fixed Line ISP', isp: 'Some ISP', isTor: false } });
    }
    if (u.startsWith('https://api.greynoise.io/')) return Response.json({ ip, classification: ip === BAD ? 'malicious' : 'unknown', noise: ip === BAD, riot: false, name: 'unknown' });
    if (u.startsWith('https://proxycheck.io/')) return Response.json({ status: 'ok', [ip]: { proxy: 'no', type: 'Residential', risk: 0, isocode: 'NL' } });
    return new Response('not found', { status: 404 });
  });
  return { f, calls };
}

const post = (body: unknown, init: { headers?: Record<string, string>; cookie?: string; sameSite?: boolean } = {}) =>
  batchPost(req('/api/v1/ip-intel/batch', { method: 'POST', body, headers: init.headers ?? admin, cookie: init.cookie, sameSite: init.sameSite }));

async function items(r: Response): Promise<BatchLookupItem[]> {
  return ((await r.json()) as { items: BatchLookupItem[] }).items;
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
  // 快照：四條可疑／危險的對外連線，連到 BAD、MEH、NEW、LAN
  const snap = load('snapshot.v1.json');
  const base = snap.connections[0];
  snap.connections = [BAD, MEH, NEW, LAN].map((ip, i) => {
    const c = structuredClone(base);
    c.remote_ip = ip;
    c.remote_port = 443 + i;
    c.verdict = { level: i === 0 ? 'dangerous' : 'suspicious', reasons: [{ type: 'anomaly', kind: 'temp_dir_process', detail: 'x' }] };
    return c;
  });
  expect((await snapshot(clientPost('/api/v1/ingest/snapshot', snap))).status).toBe(200);
});

beforeEach(async () => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_CLAUDE_BIN = FAKE;
  process.env.ASA_HUB_CODEX_BIN = path.resolve(__dirname, 'does-not-exist');
  delete process.env.ASA_HUB_IP_LOOKUPS;
  process.env.ASA_HUB_ABUSEIPDB_KEY = 'k-abuse-123456';
  resetEnvForTests();
  resetRateLimitsForTests();
  resetThrottleForTests();
  await db.delete(ipReputation);
  await db.delete(settings);
  // 反查 DNS 會走真的網路，測試裡關掉
  await db.insert(settings).values({ key: 'ipintel.config', value: { keys: {}, disabled: ['rdns'] }, updatedBy: 'test' });
  await db.delete(auditLog);
  await db.delete(ipNotes);
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.ASA_HUB_ABUSEIPDB_KEY;
});

describe('POST /api/v1/ip-intel/batch', () => {
  it('validates input, requires admin and the CSRF header for cookie sessions', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    const bad = await post({ ips: [BAD, 'nope', '1.2.3.4.5'] });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: 'bad_ip', invalid: ['nope', '1.2.3.4.5'] });
    const many = Array.from({ length: BATCH_MAX + 1 }, (_, i) => `8.8.${Math.floor(i / 250)}.${i % 250}`);
    expect((await post({ ips: many })).status).toBe(400);
    expect((await post({ ips: [] })).status).toBe(400);
    expect((await post({ ip: BAD })).status).toBe(400);
    expect((await post({ ips: [BAD] }, { headers: {} })).status).toBe(401);
    // 登入後的 cookie 身分：沒帶 x-asa-request 的跨站寫入要擋
    const ok = await login(req('/api/auth/login', { method: 'POST', body: { key: 'test-admin' } }));
    const cookie = cookieFrom(ok, 'asa_admin')!;
    expect((await post({ ips: [BAD] }, { headers: {}, cookie, sameSite: false })).status).toBe(403);
    expect(calls).toHaveLength(0);
    // 同站請求可以
    expect((await post({ ips: [BAD] }, { headers: {}, cookie })).status).toBe(200);
  });

  it('looks up public IPs, skips private ones with a reason, dedups and writes one audit entry', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    const r = await post({ ips: [BAD, LAN, MEH, BAD, '::ffff:45.155.205.233', '127.0.0.1'] });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { items: BatchLookupItem[]; summary: Record<string, number> };
    expect(body.items.map((x) => x.ip)).toEqual([BAD, LAN, MEH, '127.0.0.1']);
    expect(body.items[0]).toMatchObject({ ip: BAD, level: 'critical', cached: false });
    expect(body.items[0].score).toBeGreaterThanOrEqual(75);
    expect(body.items[1]).toMatchObject({ ip: LAN, skipped: 'not_public', score: null });
    expect(body.items[2]).toMatchObject({ ip: MEH, level: 'low', cached: false });
    expect(body.items[3]).toMatchObject({ skipped: 'not_public' });
    expect(body.summary).toEqual({ count: 4, queried: 2, cached: 0, skipped: 2, errors: 0 });
    // 內網位址絕不送出
    expect(calls.some((u) => u.includes(LAN) || u.includes('127.0.0.1'))).toBe(false);
    const audits = await db.select().from(auditLog).where(eq(auditLog.action, 'ip_intel.batch'));
    expect(audits).toHaveLength(1);
    expect(audits[0].details).toMatchObject({ count: 4, queried: 2, skipped: 2, force: false, ips: [BAD, MEH] });
  });

  it('reuses the cache, and force re-queries', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    await post({ ips: [BAD, MEH] });
    const n = calls.length;
    expect(n).toBeGreaterThan(0);
    const again = await items(await post({ ips: [BAD, MEH] }));
    expect(calls).toHaveLength(n);
    expect(again.every((x) => x.cached)).toBe(true);
    expect(again[0]).toMatchObject({ ip: BAD, level: 'critical' });
    const forced = await items(await post({ ips: [BAD], force: true }));
    expect(forced[0].cached).toBe(false);
    expect(calls.length).toBeGreaterThan(n);
  });

  it('isolates per-IP failures', async () => {
    const { f } = fakeFetch();
    vi.stubGlobal('fetch', f);
    // 某個 IP 的來源全部連不上：那個 IP 沒有分數，其他 IP 照常
    const r = await items(await post({ ips: [FLAKY, BAD] }));
    expect(r[0]).toMatchObject({ ip: FLAKY, score: null });
    expect(r[1]).toMatchObject({ ip: BAD, level: 'critical' });
    // 查詢本身拋錯（例如資料庫錯誤）：那一個 IP 帶 error，其他 IP 不受影響
    const out = await lookupBatch([MEH, BAD], {
      actor: 'test',
      lookup: async (ip, opts) => {
        if (ip === MEH) throw new Error('boom');
        return lookupIp(ip, opts);
      },
    });
    expect(out[0]).toMatchObject({ ip: MEH, error: 'boom', score: null });
    expect(out[1]).toMatchObject({ ip: BAD, level: 'critical', cached: true });
  });

  it('runs with bounded concurrency and does not lose quota counts', async () => {
    const { f } = fakeFetch();
    vi.stubGlobal('fetch', f);
    const ips = ['8.8.8.8', '8.8.4.4', '9.9.9.9', '1.0.0.1', '4.2.2.2', '4.2.2.1', '64.6.64.6'];
    let active = 0;
    let peak = 0;
    await lookupBatch(ips, {
      actor: 'test',
      lookup: async (ip, opts) => {
        active += 1;
        peak = Math.max(peak, active);
        try {
          return await lookupIp(ip, opts);
        } finally {
          active -= 1;
        }
      },
    });
    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1);
    const [q] = await db.select().from(settings).where(eq(settings.key, 'ipintel.quota'));
    const used = (q.value as { used: Record<string, number> }).used;
    // 每個來源剛好每個 IP 算一次（並行也不會少算）
    expect(used.abuseipdb).toBe(ips.length);
    expect(used.greynoise).toBe(ips.length);
    expect(used.proxycheck).toBe(ips.length);
  });

  it('honours the kill switch', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    process.env.ASA_HUB_IP_LOOKUPS = 'off';
    expect((await post({ ips: [BAD] })).status).toBe(409);
    expect(calls).toHaveLength(0);
  });
});

describe('cached risk (icons next to IPs) and the ranking column', () => {
  it('maps IPs to private / unqueried / scored from the cache only', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    await post({ ips: [BAD, MEH] });
    const n = calls.length;
    const m = await cachedRiskMap([BAD, MEH, NEW, LAN, '::ffff:45.155.205.233', null, 'garbage', BAD]);
    expect(calls).toHaveLength(n);
    const bad = m.get(BAD) as Extract<IpRisk, { kind: 'scored' }>;
    expect(bad).toMatchObject({ kind: 'scored', level: 'critical' });
    expect(Date.parse(bad.queriedAt)).toBeGreaterThan(0);
    expect(m.get(MEH)).toMatchObject({ kind: 'scored', level: 'low' });
    expect(m.get(NEW)).toEqual({ kind: 'unqueried' });
    expect(m.get(LAN)).toEqual({ kind: 'private' });
    expect(m.get('::ffff:45.155.205.233')).toMatchObject({ kind: 'scored', level: 'critical' });
    expect(m.has('garbage')).toBe(false);
    expect((await cachedRiskMap([])).size).toBe(0);
  });

  it('shows the risk per row and sorts by it, never-queried last', async () => {
    const { f } = fakeFetch();
    vi.stubGlobal('fetch', f);
    const before = await riskyIpRanking(10);
    expect(before.items.find((x) => x.remoteIp === BAD)?.risk).toEqual({ kind: 'unqueried' });
    expect(before.items.find((x) => x.remoteIp === LAN)?.risk).toEqual({ kind: 'private' });

    await post({ ips: [BAD, MEH] });
    const desc = await riskyIpRanking(10, undefined, { key: 'risk', dir: 'desc' });
    expect(desc.items.map((x) => x.remoteIp).slice(0, 2)).toEqual([BAD, MEH]);
    expect(desc.items.map((x) => x.rank)).toEqual([1, 2, 3, 4]);
    expect(desc.items[0].risk).toMatchObject({ kind: 'scored', level: 'critical' });
    const asc = await riskyIpRanking(10, undefined, { key: 'risk', dir: 'asc' });
    expect(asc.items.map((x) => x.remoteIp).slice(0, 2)).toEqual([MEH, BAD]);
    // 沒查過與內網一律排在最後
    expect(new Set(asc.items.slice(2).map((x) => x.remoteIp))).toEqual(new Set([NEW, LAN]));
    // limit 照樣生效
    expect((await riskyIpRanking(1, undefined, { key: 'risk', dir: 'desc' })).items.map((x) => x.remoteIp)).toEqual([BAD]);
  });
});

describe('AI scope with several IPs', () => {
  const run = (body: unknown) => streamRoute(req('/api/ai/stream', { method: 'POST', headers: admin, body }));

  it('validates the IP list', async () => {
    expect((await run({ scope: 'ips' })).status).toBe(400);
    expect((await run({ scope: 'ips', ips: [] })).status).toBe(400);
    expect((await run({ scope: 'ips', ips: [BAD, 'evil; rm -rf /'] })).status).toBe(400);
    expect((await run({ scope: 'ips', ips: Array.from({ length: 21 }, (_, i) => `8.8.8.${i}`) })).status).toBe(400);
  });

  it('feeds each IP\'s records, note and cached external intel into the prompt', async () => {
    const { f } = fakeFetch();
    vi.stubGlobal('fetch', f);
    await post({ ips: [BAD] });
    await db.insert(ipNotes).values({ ip: MEH, note: 'GitHub Pages，已確認', updatedBy: 'admin:bearer' });
    const callsBefore = f.mock.calls.length;
    const res = await run({ scope: 'ips', ips: [BAD, MEH, LAN, BAD] });
    expect(res.status).toBe(200);
    const text = await res.text();
    const end = text
      .split('\n\n')
      .filter((c) => c.startsWith('data: '))
      .map((c) => JSON.parse(c.slice(6)))
      .at(-1);
    expect(end).toMatchObject({ type: 'end', status: 'done' });
    // 建立提示時只讀快取，不會打外部 API
    expect(f.mock.calls.length).toBe(callsBefore);
    const [row] = await db.select().from(aiAnalyses).where(eq(aiAnalyses.id, end.id));
    expect(row.scope).toBe('ips');
    expect(row.prompt).toContain(`IPs (3): ${BAD}, ${MEH}, ${LAN}`);
    expect(row.prompt).toContain('<ip_data>');
    const lines = row.prompt.split('<ip_data>\n')[1].split('\n</ip_data>')[0].split('\n').map((l) => JSON.parse(l));
    expect(lines.map((l) => l.ip)).toEqual([BAD, MEH, LAN]);
    expect(lines[0].external_intel).toMatchObject({ risk_level: 'critical' });
    expect(lines[0].history[0]).toMatchObject({ worst_verdict: 'dangerous', remote_port: 443 });
    expect(lines[1]).toMatchObject({ note: 'GitHub Pages，已確認', external_intel: 'not queried yet' });
    expect(lines[2].external_intel).toContain('private');
  });
});
