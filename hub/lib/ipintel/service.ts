// IP 外部情資：金鑰設定、每日額度、快取、查詢與畫面用的彙整。
// 原則：hub 不會自動把 IP 送給第三方，只有管理員在 IP 分析頁按「查詢」（POST /api/v1/ip-intel）才會打外部 API。
import dns from 'node:dns/promises';
import { isIP } from 'node:net';
import { desc, eq } from 'drizzle-orm';
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
import { PROVIDER_IDS, type IpIntelView, type LocalHit, type Profile, type ProviderId, type ProviderResult, type ProviderView, type SourcesConfigStatus } from './types';

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
  const quota = await readQuota();
  const queried: ProviderId[] = [];

  await Promise.all(
    PROVIDERS.map(async (p) => {
      if (cfg.disabled.includes(p.id) || (v6 && !p.ipv6)) return;
      const { key } = keyFor(p, cfg);
      if (p.key === 'required' && !key) return;
      const prev = results[p.id];
      if (!opts.refresh && prev?.ok && Date.now() - Date.parse(prev.fetchedAt) < p.ttlMs) return;
      const limit = key && p.quotaWithKey ? p.quotaWithKey : p.quota;
      if ((quota.used[p.id] ?? 0) >= limit) {
        results[p.id] = { ok: false, reason: 'quota-exhausted', detail: `${limit}/day`, fetchedAt: new Date().toISOString() };
        return;
      }
      quota.used[p.id] = (quota.used[p.id] ?? 0) + 1;
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

  if (queried.length) await writeQuota(quota);
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
