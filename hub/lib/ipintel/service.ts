// IP 外部情資：金鑰設定、每日額度、快取、查詢與畫面用的彙整。
// 原則：hub 不會自動把 IP 送給第三方，只有管理員在 IP 分析頁按「查詢」（POST /api/v1/ip-intel）才會打外部 API。
import dns from 'node:dns/promises';
import { isIP } from 'node:net';
import { desc, eq, inArray, sql } from 'drizzle-orm';
import { destinations, intelHits, ipReputation, settings } from '@/drizzle/schema';
import { getDb } from '@/lib/db';
import { readEnv } from '@/lib/env';
import { isPublicIp, normalizeIp } from './ip';
import {
  PROVIDERS,
  callAbuseipdb,
  callGreynoise,
  callIpinfo,
  callProxycheck,
  callRdns,
  looksLikeDatacenter,
  type DnsFns,
  type FetchFn,
  type ProviderMeta,
} from './providers';
import { scoreIp } from './score';
import { PROVIDER_IDS, type BatchLookupItem, type IpIntelView, type IpRisk, type LocalHit, type Profile, type ProviderId, type ProviderResult, type ProviderView, type SourcesConfigStatus } from './types';

const CONFIG_KEY = 'ipintel.config';
const QUOTA_KEY = 'ipintel.quota';
const TIMEOUT_MS = 8000;

export interface IpIntelConfig {
  keys: Partial<Record<ProviderId, string>>;
  disabled: ProviderId[];
}

/** `ASA_HUB_IP_LOOKUPS=off` 完全關掉外部查詢（離線環境）。 */
export function lookupsEnabled(): boolean {
  return !['0', 'off', 'false', 'no'].includes(readEnv('ASA_HUB_IP_LOOKUPS').toLowerCase());
}

export async function getConfig(): Promise<IpIntelConfig> {
  const [row] = await getDb().select().from(settings).where(eq(settings.key, CONFIG_KEY)).limit(1);
  const v = (row?.value ?? {}) as Partial<IpIntelConfig>;
  const keys: IpIntelConfig['keys'] = {};
  for (const id of PROVIDER_IDS) {
    const k = v.keys?.[id];
    if (typeof k === 'string' && k) keys[id] = k;
  }
  const disabled = Array.isArray(v.disabled) ? v.disabled.filter((x): x is ProviderId => (PROVIDER_IDS as readonly string[]).includes(x)) : [];
  return { keys, disabled };
}

export async function saveConfig(cfg: IpIntelConfig, actor: string): Promise<void> {
  await getDb()
    .insert(settings)
    .values({ key: CONFIG_KEY, value: cfg, updatedBy: actor })
    .onConflictDoUpdate({ target: settings.key, set: { value: cfg, updatedAt: new Date(), updatedBy: actor } });
}

/** 金鑰：環境變數優先，其次是網頁上存的。 */
export function keyFor(meta: ProviderMeta, cfg: IpIntelConfig): { key: string | null; source: 'env' | 'settings' | null } {
  const fromEnv = meta.env ? readEnv(meta.env) : '';
  if (fromEnv) return { key: fromEnv, source: 'env' };
  const saved = cfg.keys[meta.id];
  return saved ? { key: saved, source: 'settings' } : { key: null, source: null };
}

export function maskKey(k: string): string {
  return k.length <= 8 ? '••••' : `${k.slice(0, 3)}••••${k.slice(-3)}`;
}

/** 設定頁用：每個來源的金鑰狀態（不回傳明文）。 */
export async function configStatus(): Promise<SourcesConfigStatus> {
  const cfg = await getConfig();
  const quota = await readQuota();
  return {
    lookupsEnabled: lookupsEnabled(),
    providers: PROVIDERS.map((p) => {
      const k = keyFor(p, cfg);
      return {
        id: p.id,
        name: p.name,
        key: p.key,
        env: p.env,
        keySource: k.source,
        keyHint: k.key ? maskKey(k.key) : null,
        enabled: !cfg.disabled.includes(p.id),
        quota: k.key && p.quotaWithKey ? p.quotaWithKey : p.quota,
        usedToday: quota.used[p.id] ?? 0,
        signup: p.signup,
      };
    }),
  };
}

// ---- 每日額度 ----

const today = () => new Date().toISOString().slice(0, 10);

async function readQuota(): Promise<{ date: string; used: Partial<Record<ProviderId, number>> }> {
  const [row] = await getDb().select().from(settings).where(eq(settings.key, QUOTA_KEY)).limit(1);
  const v = row?.value as { date?: string; used?: Partial<Record<ProviderId, number>> } | undefined;
  return v?.date === today() ? { date: v.date, used: v.used ?? {} } : { date: today(), used: {} };
}

async function writeQuota(q: { date: string; used: Partial<Record<ProviderId, number>> }): Promise<void> {
  await getDb()
    .insert(settings)
    .values({ key: QUOTA_KEY, value: q, updatedBy: 'system' })
    .onConflictDoUpdate({ target: settings.key, set: { value: q, updatedAt: new Date(), updatedBy: 'system' } });
}

// 同一個行程裡額度的讀改寫排隊進行（批次查詢會並行好幾個 IP）。
let quotaChain: Promise<unknown> = Promise.resolve();

/** 預留這些來源各 1 次額度；回傳拿到額度的來源（→ 預留後的已用次數），額度用完的不在裡面。 */
async function reserveQuota(want: ProviderMeta[], cfg: IpIntelConfig): Promise<Map<ProviderId, number>> {
  const run = quotaChain.then(async () => {
    const quota = await readQuota();
    const granted = new Map<ProviderId, number>();
    for (const p of want) {
      const { key } = keyFor(p, cfg);
      const limit = key && p.quotaWithKey ? p.quotaWithKey : p.quota;
      const used = quota.used[p.id] ?? 0;
      if (used >= limit) continue;
      quota.used[p.id] = used + 1;
      granted.set(p.id, used + 1);
    }
    if (granted.size) await writeQuota(quota);
    return granted;
  });
  quotaChain = run.catch(() => undefined);
  return run;
}

// ---- 查詢 ----

export interface LookupDeps {
  fetch?: FetchFn;
  dns?: DnsFns;
}

const systemDns: DnsFns = {
  reverse: (ip) => dns.reverse(ip),
  resolve: async (host) => (await dns.lookup(host, { all: true })).map((a) => a.address),
};

export class NotPublicIp extends Error {}
export class LookupsDisabled extends Error {}

/**
 * 對外部來源查一個 IP（快取內的結果不重打，refresh 時強制重打），寫回 ip_reputation 後回傳畫面資料。
 * 回傳 `queried`：這次實際打了哪些來源。
 */
export async function lookupIp(
  input: string,
  opts: { refresh?: boolean; actor: string; deps?: LookupDeps },
): Promise<{ view: IpIntelView; queried: ProviderId[] }> {
  const ip = normalizeIp(input);
  if (!isPublicIp(ip)) throw new NotPublicIp(ip);
  if (!lookupsEnabled()) throw new LookupsDisabled();
  const f = opts.deps?.fetch ?? fetch;
  const resolver = opts.deps?.dns ?? systemDns;
  const v6 = isIP(ip) === 6;
  const db = getDb();
  const cfg = await getConfig();
  const [row] = await db.select().from(ipReputation).where(eq(ipReputation.ip, ip)).limit(1);
  const results = { ...((row?.results ?? {}) as Partial<Record<ProviderId, ProviderResult>>) };
  // 先決定要打哪些來源，再一次預留額度（批次查詢會同時跑好幾個 IP，額度的讀改寫要排隊才不會少算）
  const want: ProviderMeta[] = [];
  for (const p of PROVIDERS) {
    if (cfg.disabled.includes(p.id) || (v6 && !p.ipv6)) continue;
    const { key } = keyFor(p, cfg);
    if (p.key === 'required' && !key) continue;
    const prev = results[p.id];
    if (!opts.refresh && prev?.ok && Date.now() - Date.parse(prev.fetchedAt) < p.ttlMs) continue;
    want.push(p);
  }
  const granted = want.length ? await reserveQuota(want, cfg) : new Map<ProviderId, number>();
  const queried: ProviderId[] = [];

  await Promise.all(
    want.map(async (p) => {
      const { key } = keyFor(p, cfg);
      const prev = results[p.id];
      if (!granted.has(p.id)) {
        const limit = key && p.quotaWithKey ? p.quotaWithKey : p.quota;
        results[p.id] = { ok: false, reason: 'quota-exhausted', detail: `${limit}/day`, fetchedAt: new Date().toISOString() };
        return;
      }
      queried.push(p.id);
      const call = { ip, key, fetch: f, timeoutMs: TIMEOUT_MS };
      const r =
        p.id === 'abuseipdb'
          ? await callAbuseipdb(call)
          : p.id === 'greynoise'
            ? await callGreynoise(call)
            : p.id === 'ipinfo'
              ? await callIpinfo(call)
              : p.id === 'proxycheck'
                ? await callProxycheck(call)
                : await callRdns(ip, resolver, TIMEOUT_MS);
      // 失敗時保留上一次成功的資料（標示錯誤原因），不要讓一次逾時把舊情資洗掉
      results[p.id] = r.ok || !prev?.ok ? r : { ...prev, ok: true, detail: `${r.reason}: ${r.detail ?? ''}`.slice(0, 200) };
    }),
  );

  const now = new Date();
  await db
    .insert(ipReputation)
    .values({ ip, results, queriedAt: now, queriedBy: opts.actor })
    .onConflictDoUpdate({ target: ipReputation.ip, set: { results, queriedAt: now, queriedBy: opts.actor } });
  return { view: await getIpIntelView(ip), queried };
}

// ---- 畫面資料 ----

/** 欄位合併順序：前面的來源優先（ipinfo 的 ASN／國家最準）。 */
const MERGE_ORDER: ProviderId[] = ['ipinfo', 'proxycheck', 'abuseipdb', 'greynoise', 'rdns'];

export function mergeProfile(results: Partial<Record<ProviderId, ProviderResult>>, local: Profile = {}): Profile {
  const out: Record<string, unknown> = {};
  for (const id of MERGE_ORDER) {
    const d = results[id]?.ok ? results[id]?.data : undefined;
    if (!d) continue;
    for (const [k, v] of Object.entries(d)) if (out[k] === undefined && v !== undefined) out[k] = v;
  }
  const p = out as Profile;
  // 用途分類以 AbuseIPDB 為準
  const ab = results.abuseipdb?.ok ? results.abuseipdb.data : undefined;
  if (ab?.usageType !== undefined) p.usageType = ab.usageType;
  if (ab?.isDatacenter !== undefined) p.isDatacenter = ab.isDatacenter;
  // 沒有外部資料時用 agent 本機 GeoIP（DB-IP lite）補國家／ASN
  for (const k of ['country', 'asn', 'asnOrg'] as const) {
    if (p[k] == null && local[k] != null) (p as Record<string, unknown>)[k] = local[k];
  }
  if (p.isDatacenter === undefined) {
    const guess = looksLikeDatacenter(p.asnOrg, p.isp, p.hostname);
    if (guess !== null) p.isDatacenter = guess;
  }
  return p;
}

function hitOf(id: ProviderId, r: ProviderResult | null): boolean | null {
  if (!r?.ok || !r.data) return null;
  const d = r.data;
  if (id === 'abuseipdb') return (d.abuseScore ?? 0) >= 25;
  if (id === 'greynoise') return d.greynoiseClass === 'malicious' || d.greynoiseClass === 'suspicious';
  if (id === 'proxycheck') return Boolean(d.isProxy || d.isVpn);
  // ipinfo／DNS 只提供背景資料，不算命中
  return false;
}

export async function localHitsFor(ip: string): Promise<LocalHit[]> {
  const rows = await getDb()
    .select({
      feedId: intelHits.feedId,
      feedName: intelHits.feedName,
      vendor: intelHits.vendor,
      confidence: intelHits.confidence,
      sourceUrl: intelHits.sourceUrl,
    })
    .from(intelHits)
    .where(eq(intelHits.indicator, ip))
    .orderBy(desc(intelHits.seenAt))
    .limit(200);
  const byFeed = new Map<string, LocalHit>();
  for (const r of rows) {
    const cur = byFeed.get(r.feedId);
    if (!cur || r.confidence > cur.confidence) byFeed.set(r.feedId, r);
  }
  return [...byFeed.values()];
}

async function localGeo(ip: string): Promise<Profile> {
  const [d] = await getDb()
    .select({ country: destinations.country, asn: destinations.asn, org: destinations.org })
    .from(destinations)
    .where(eq(destinations.remoteIp, ip))
    .orderBy(desc(destinations.lastSeenAt))
    .limit(1);
  return d ? { country: d.country, asn: d.asn, asnOrg: d.org } : {};
}

/** 只讀快取與本機資料，不打任何外部 API。 */
export async function getIpIntelView(input: string): Promise<IpIntelView> {
  const ip = normalizeIp(input);
  const isPublic = isPublicIp(ip);
  const v6 = isIP(ip) === 6;
  const enabled = lookupsEnabled();
  const [cfg, [row], localHits, geo] = await Promise.all([
    getConfig(),
    getDb().select().from(ipReputation).where(eq(ipReputation.ip, ip)).limit(1),
    localHitsFor(ip),
    localGeo(ip),
  ]);
  const results = (row?.results ?? {}) as Partial<Record<ProviderId, ProviderResult>>;
  const providers: ProviderView[] = PROVIDERS.map((p) => {
    const configured = Boolean(keyFor(p, cfg).key);
    const on = !cfg.disabled.includes(p.id);
    const result = results[p.id] ?? null;
    return {
      id: p.id,
      name: p.name,
      key: p.key,
      configured,
      enabled: on,
      willQuery: isPublic && enabled && on && (p.key !== 'required' || configured) && (!v6 || p.ipv6),
      result,
      hit: hitOf(p.id, result),
      link: p.link ? p.link(ip) : null,
    };
  });
  const queried = providers.some((p) => p.result?.ok);
  const profile = mergeProfile(results, geo);
  return {
    ip,
    isPublic,
    lookupsEnabled: enabled,
    queriedAt: row ? row.queriedAt.toISOString() : null,
    providers,
    localHits,
    profile,
    score: scoreIp(profile, localHits, queried),
  };
}

// ---- 批次 ----

export const BATCH_MAX = 50;
export const BATCH_CONCURRENCY = 3;

/**
 * 一次查多個 IP（呼叫端已驗證格式、去重）：最多同時查 BATCH_CONCURRENCY 個，快取與每日額度照常；
 * 內網／保留位址直接略過、某個 IP 失敗不影響其他 IP。每個來源本來就有逾時，慢的來源不會卡住整批。
 */
export async function lookupBatch(
  ips: string[],
  opts: { refresh?: boolean; actor: string; deps?: LookupDeps; concurrency?: number; lookup?: typeof lookupIp },
): Promise<BatchLookupItem[]> {
  const lookup = opts.lookup ?? lookupIp;
  if (!lookupsEnabled()) throw new LookupsDisabled();
  const out: BatchLookupItem[] = new Array(ips.length);
  const seen = new Set<string>();
  const todo: number[] = [];
  ips.forEach((raw, i) => {
    const ip = normalizeIp(raw);
    if (seen.has(ip)) out[i] = { ip, score: null, level: null, cached: true, skipped: 'duplicate' };
    else if (!isPublicIp(ip)) out[i] = { ip, score: null, level: null, cached: true, skipped: 'not_public' };
    else todo.push(i);
    seen.add(ip);
  });
  let next = 0;
  const worker = async () => {
    while (next < todo.length) {
      const i = todo[next++];
      const ip = normalizeIp(ips[i]);
      try {
        const r = await lookup(ip, { refresh: opts.refresh, actor: opts.actor, deps: opts.deps });
        out[i] = { ip, score: r.view.score?.score ?? null, level: r.view.score?.level ?? null, cached: r.queried.length === 0 };
      } catch (e) {
        out[i] = { ip, score: null, level: null, cached: false, error: e instanceof Error ? e.message.slice(0, 200) : String(e).slice(0, 200) };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(opts.concurrency ?? BATCH_CONCURRENCY, todo.length)) }, worker));
  return out;
}

/**
 * 多個 IP 的快取風險（清單頁 IP 旁的圖示、排名的「外部風險」欄）：只讀 ip_reputation／intel_hits／destinations，
 * 用跟 IP 分析頁同一套 mergeProfile＋scoreIp 算分。key 是傳進來的原字串。
 */
export async function cachedRiskMap(input: (string | null | undefined)[]): Promise<Map<string, IpRisk>> {
  const out = new Map<string, IpRisk>();
  const norm = new Map<string, string>();
  for (const raw of input) {
    if (!raw || norm.has(raw) || !isIP(normalizeIp(raw))) continue;
    norm.set(raw, normalizeIp(raw));
  }
  const pub = [...new Set([...norm.values()].filter(isPublicIp))];
  const db = getDb();
  const rows = pub.length
    ? await db.select({ ip: ipReputation.ip, results: ipReputation.results, queriedAt: ipReputation.queriedAt }).from(ipReputation).where(inArray(ipReputation.ip, pub))
    : [];
  const queried = rows.map((r) => r.ip);
  const [hitRows, geoRows] = queried.length
    ? await Promise.all([
        db
          .select({
            ip: intelHits.indicator,
            feedId: intelHits.feedId,
            feedName: sql<string>`max(${intelHits.feedName})`,
            vendor: sql<string>`max(${intelHits.vendor})`,
            confidence: sql<number>`max(${intelHits.confidence})::int`,
            sourceUrl: sql<string>`max(${intelHits.sourceUrl})`,
          })
          .from(intelHits)
          .where(inArray(intelHits.indicator, queried))
          .groupBy(intelHits.indicator, intelHits.feedId),
        db
          .selectDistinctOn([destinations.remoteIp], { ip: destinations.remoteIp, country: destinations.country, asn: destinations.asn, org: destinations.org })
          .from(destinations)
          .where(inArray(destinations.remoteIp, queried))
          .orderBy(destinations.remoteIp, desc(destinations.lastSeenAt)),
      ])
    : [[], []];
  const hits = new Map<string, LocalHit[]>();
  for (const h of hitRows) hits.set(h.ip, [...(hits.get(h.ip) ?? []), { feedId: h.feedId, feedName: h.feedName, vendor: h.vendor, confidence: Number(h.confidence), sourceUrl: h.sourceUrl }]);
  const geo = new Map(geoRows.map((g) => [g.ip, { country: g.country, asn: g.asn, asnOrg: g.org } as Profile]));
  const scored = new Map<string, IpRisk>();
  for (const r of rows) {
    const results = (r.results ?? {}) as Partial<Record<ProviderId, ProviderResult>>;
    const any = Object.values(results).some((x) => x?.ok);
    const s = scoreIp(mergeProfile(results, geo.get(r.ip)), hits.get(r.ip) ?? [], any);
    scored.set(r.ip, s ? { kind: 'scored', score: s.score, level: s.level, queriedAt: r.queriedAt.toISOString() } : { kind: 'unqueried' });
  }
  for (const [raw, ip] of norm) out.set(raw, !isPublicIp(ip) ? { kind: 'private' } : (scored.get(ip) ?? { kind: 'unqueried' }));
  return out;
}

/** 同上，回傳一般物件（給 props 用）。 */
export async function cachedRisks(input: (string | null | undefined)[]): Promise<Record<string, IpRisk>> {
  return Object.fromEntries(await cachedRiskMap(input));
}
