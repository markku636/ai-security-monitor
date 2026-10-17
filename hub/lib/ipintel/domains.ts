// IP 上的網域：主機自己解析過的（agent 快照帶上來的 DNS 快取）＋外部被動 DNS 反查（HackerTarget、VirusTotal、AlienVault OTX）。
// 原則同外部情資：外部來源只有管理員在 IP 分析頁按「查詢網域」才會打；結果存在 ip_domain_lookups（跟風險分數的快取分開）。
import { isIP } from 'node:net';
import { desc, eq, inArray, lt, sql } from 'drizzle-orm';
import { agents, ipDomainLookups, ipDomains, ipReputation } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { getDb } from '@/lib/db';
import { isPublicIp, normalizeIp } from './ip';
import { DOMAIN_PROVIDERS, type FetchFn, type ProviderMeta } from './providers';
import { LookupsDisabled, NotPublicIp, getConfig, keyFor, lookupsEnabled, reserveQuota } from './service';
import type { DomainItem, DomainList, IpDomainsView, ProviderId, ProviderResult, ProviderView } from './types';

const TIMEOUT_MS = 10_000;
/** 每個來源最多存幾個網域（CDN／共用主機上可能有幾萬個）。 */
export const MAX_STORED = 200;
/** 主機解析過的網域保留天數。 */
export const LOCAL_RETENTION_DAYS = 30;

/** 正規化網域：小寫、去結尾的點；不像網域（沒有點、太長、怪字元、arpa）回 null。 */
export function normalizeDomain(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const n = raw.trim().replace(/\.$/, '').toLowerCase();
  if (n.length < 3 || n.length > 253 || !n.includes('.') || n.endsWith('.arpa')) return null;
  return n.split('.').every((l) => l.length > 0 && l.length <= 63 && /^[a-z0-9_-]+$/.test(l)) ? n : null;
}

/** 去重、依最後看到時間排（新的在前，沒有時間的放後面），只留前 MAX_STORED 個。 */
function toList(items: DomainItem[], total?: number | null): DomainList {
  const best = new Map<string, DomainItem>();
  for (const it of items) {
    const prev = best.get(it.name);
    if (!prev || (it.lastSeen ?? '') > (prev.lastSeen ?? '')) best.set(it.name, it);
  }
  const sorted = [...best.values()].sort((a, b) => (b.lastSeen ?? '').localeCompare(a.lastSeen ?? '') || a.name.localeCompare(b.name));
  return { total: Math.max(total ?? 0, sorted.length), items: sorted.slice(0, MAX_STORED) };
}

const isoOf = (v: unknown): string | null => {
  if (typeof v === 'number' && Number.isFinite(v) && v > 0) return new Date(v * 1000).toISOString();
  if (typeof v === 'string' && v.trim()) {
    const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(v) ? v : `${v.trim().replace(' ', 'T')}Z`);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  return null;
};

// ---- 解析（純函式，測試用固定回應） ----

export type TextParse = { ok: true; list: DomainList } | { ok: false; reason: 'quota-exhausted' | 'http-error'; detail: string };

/** HackerTarget reverseiplookup：純文字，一行一個網域；沒有結果、額度用完、錯誤都是一句話。 */
export function parseHackertarget(text: string): TextParse {
  const body = text.trim();
  if (/api count exceeded|increase quota/i.test(body)) return { ok: false, reason: 'quota-exhausted', detail: body.slice(0, 200) };
  if (/^no (dns a )?records found/i.test(body) || body === '') return { ok: true, list: { total: 0, items: [] } };
  if (/^error/i.test(body)) return { ok: false, reason: 'http-error', detail: body.slice(0, 200) };
  const items: DomainItem[] = [];
  for (const line of body.split(/\r?\n/)) {
    const name = normalizeDomain(line);
    if (name) items.push({ name, lastSeen: null });
  }
  return { ok: true, list: toList(items) };
}

/** VirusTotal v3 /ip_addresses/{ip}/resolutions。 */
export function parseVirustotal(body: unknown): DomainList | null {
  const b = body as { data?: unknown; meta?: { count?: unknown } } | null;
  if (!b || !Array.isArray(b.data)) return null;
  const items: DomainItem[] = [];
  for (const row of b.data as Array<{ attributes?: Record<string, unknown> }>) {
    const name = normalizeDomain(row?.attributes?.host_name);
    if (name) items.push({ name, lastSeen: isoOf(row.attributes?.date) });
  }
  const count = typeof b.meta?.count === 'number' ? b.meta.count : null;
  return toList(items, count);
}

/** AlienVault OTX /indicators/IPv4|IPv6/{ip}/passive_dns（只取 A／AAAA）。 */
export function parseOtx(body: unknown): DomainList | null {
  const b = body as { passive_dns?: unknown; count?: unknown } | null;
  if (!b || !Array.isArray(b.passive_dns)) return null;
  const items: DomainItem[] = [];
  for (const row of b.passive_dns as Array<Record<string, unknown>>) {
    const type = typeof row?.record_type === 'string' ? row.record_type.toUpperCase() : 'A';
    if (type !== 'A' && type !== 'AAAA') continue;
    const name = normalizeDomain(row.hostname);
    if (name) items.push({ name, lastSeen: isoOf(row.last) });
  }
  return toList(items, typeof b.count === 'number' ? b.count : null);
}

// ---- 呼叫 ----

const now = () => new Date().toISOString();
const fail = (reason: NonNullable<ProviderResult['reason']>, detail?: string): ProviderResult => ({ ok: false, reason, detail, fetchedAt: now() });

async function get(f: FetchFn, url: string, headers: Record<string, string>): Promise<{ ok: true; status: number; text: string } | { ok: false; r: ProviderResult }> {
  try {
    const res = await f(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (res.status === 429) return { ok: false, r: fail('quota-exhausted', 'HTTP 429') };
    if (res.status === 401 || res.status === 403) return { ok: false, r: fail('http-error', `HTTP ${res.status} (bad key or no access)`) };
    if (!res.ok && res.status !== 404) return { ok: false, r: fail('http-error', `HTTP ${res.status}`) };
    return { ok: true, status: res.status, text: await res.text() };
  } catch (e) {
    const name = e instanceof Error ? e.name : '';
    return { ok: false, r: fail(name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'http-error', String(e).slice(0, 200)) };
  }
}

function json(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

const empty = (): ProviderResult => ({ ok: true, fetchedAt: now(), domains: { total: 0, items: [] } });

export async function callDomainProvider(p: ProviderMeta, ip: string, key: string | null, f: FetchFn): Promise<ProviderResult> {
  const e = encodeURIComponent(ip);
  if (p.id === 'hackertarget') {
    const g = await get(f, `https://api.hackertarget.com/reverseiplookup/?q=${e}${key ? `&apikey=${encodeURIComponent(key)}` : ''}`, {});
    if (!g.ok) return g.r;
    const r = parseHackertarget(g.text);
    return r.ok ? { ok: true, fetchedAt: now(), domains: r.list } : fail(r.reason, r.detail);
  }
  if (p.id === 'virustotal') {
    if (!key) return fail('no-api-key');
    const g = await get(f, `https://www.virustotal.com/api/v3/ip_addresses/${e}/resolutions?limit=40`, { 'x-apikey': key, accept: 'application/json' });
    if (!g.ok) return g.r;
    if (g.status === 404) return empty();
    const list = parseVirustotal(json(g.text));
    return list ? { ok: true, fetchedAt: now(), domains: list } : fail('parse-error');
  }
  if (p.id === 'otx') {
    const kind = isIP(ip) === 6 ? 'IPv6' : 'IPv4';
    const g = await get(f, `https://otx.alienvault.com/api/v1/indicators/${kind}/${e}/passive_dns`, {
      accept: 'application/json',
      ...(key ? { 'X-OTX-API-KEY': key } : {}),
    });
    if (!g.ok) return g.r;
    if (g.status === 404) return empty();
    const list = parseOtx(json(g.text));
    return list ? { ok: true, fetchedAt: now(), domains: list } : fail('parse-error');
  }
  return fail('unsupported');
}

/**
 * 對外部被動 DNS 來源查這個 IP 上的網域（快取內的不重打，refresh 時強制重打），寫回 ip_domain_lookups。
 * 回傳 `queried`：這次實際打了哪些來源。
 */
export async function lookupDomains(
  input: string,
  opts: { refresh?: boolean; actor: string; fetch?: FetchFn },
): Promise<{ view: IpDomainsView; queried: ProviderId[] }> {
  const ip = normalizeIp(input);
  if (!isPublicIp(ip)) throw new NotPublicIp(ip);
  if (!lookupsEnabled()) throw new LookupsDisabled();
  const f = opts.fetch ?? fetch;
  const v6 = isIP(ip) === 6;
  const db = getDb();
  const cfg = await getConfig();
  const [row] = await db.select().from(ipDomainLookups).where(eq(ipDomainLookups.ip, ip)).limit(1);
  const results = { ...((row?.results ?? {}) as Partial<Record<ProviderId, ProviderResult>>) };
  const want: ProviderMeta[] = [];
  for (const p of DOMAIN_PROVIDERS) {
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
        results[p.id] = { ok: false, reason: 'quota-exhausted', detail: `${limit}/day`, fetchedAt: now() };
        return;
      }
      queried.push(p.id);
      const r = await callDomainProvider(p, ip, key, f);
      // 失敗時保留上一次成功的清單（標示錯誤原因）
      results[p.id] = r.ok || !prev?.ok ? r : { ...prev, ok: true, detail: `${r.reason}: ${r.detail ?? ''}`.slice(0, 200) };
    }),
  );
  const at = new Date();
  await db
    .insert(ipDomainLookups)
    .values({ ip, results, queriedAt: at, queriedBy: opts.actor })
    .onConflictDoUpdate({ target: ipDomainLookups.ip, set: { results, queriedAt: at, queriedBy: opts.actor } });
  return { view: await getIpDomainsView(ip), queried };
}

/** 只讀快取與主機回報的資料，不打外部 API。 */
export async function getIpDomainsView(input: string): Promise<IpDomainsView> {
  const ip = normalizeIp(input);
  const isPublic = isPublicIp(ip);
  const v6 = isIP(ip) === 6;
  const enabled = lookupsEnabled();
  const db = getDb();
  const [cfg, [row], [rep], localRows] = await Promise.all([
    getConfig(),
    db.select().from(ipDomainLookups).where(eq(ipDomainLookups.ip, ip)).limit(1),
    db.select({ results: ipReputation.results }).from(ipReputation).where(eq(ipReputation.ip, ip)).limit(1),
    db
      .select({ domain: ipDomains.domain, hostname: agents.hostname, lastSeenAt: ipDomains.lastSeenAt })
      .from(ipDomains)
      .innerJoin(agents, eq(agents.id, ipDomains.agentId))
      .where(eq(ipDomains.ip, ip))
      .orderBy(desc(ipDomains.lastSeenAt))
      .limit(500),
  ]);
  const local = new Map<string, { domain: string; hosts: string[]; lastSeenAt: string }>();
  for (const r of localRows) {
    const cur = local.get(r.domain);
    if (!cur) local.set(r.domain, { domain: r.domain, hosts: [r.hostname], lastSeenAt: r.lastSeenAt.toISOString() });
    else if (!cur.hosts.includes(r.hostname)) cur.hosts.push(r.hostname);
  }
  const rdns = (rep?.results as Partial<Record<ProviderId, ProviderResult>> | undefined)?.rdns;
  const results = (row?.results ?? {}) as Partial<Record<ProviderId, ProviderResult>>;
  const providers: ProviderView[] = DOMAIN_PROVIDERS.map((p) => {
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
      hit: result?.ok ? (result.domains?.total ?? 0) > 0 : null,
      link: p.link ? p.link(ip) : null,
    };
  });
  const merged = new Map<string, { name: string; sources: ProviderId[]; lastSeen: string | null }>();
  let total = 0;
  for (const p of providers) {
    const list = p.result?.ok ? p.result.domains : undefined;
    if (!list) continue;
    total = Math.max(total, list.total);
    for (const it of list.items) {
      const cur = merged.get(it.name);
      if (!cur) merged.set(it.name, { name: it.name, sources: [p.id], lastSeen: it.lastSeen });
      else {
        if (!cur.sources.includes(p.id)) cur.sources.push(p.id);
        if ((it.lastSeen ?? '') > (cur.lastSeen ?? '')) cur.lastSeen = it.lastSeen;
      }
    }
  }
  return {
    ip,
    isPublic,
    lookupsEnabled: enabled,
    queriedAt: row ? row.queriedAt.toISOString() : null,
    local: [...local.values()],
    ptr: rdns?.ok ? (rdns.data?.hostname ?? null) : null,
    providers,
    merged: [...merged.values()]
      .sort((a, b) => b.sources.length - a.sources.length || (b.lastSeen ?? '').localeCompare(a.lastSeen ?? '') || a.name.localeCompare(b.name))
      .slice(0, MAX_STORED),
    total: Math.max(total, merged.size),
  };
}

// ---- 主機回報（快照 dns_names） ----

/** 快照帶的 IP → 網域：只收這次快照裡真的有連線的 IP、像樣的網域，每個 IP 最多 10 個。 */
export async function recordLocalDomains(db: DB, agentId: string, dnsNames: Record<string, string[]> | undefined, remoteIps: Set<string>, at: Date): Promise<number> {
  if (!dnsNames) return 0;
  const rows: (typeof ipDomains.$inferInsert)[] = [];
  const seen = new Set<string>();
  for (const [rawIp, names] of Object.entries(dnsNames)) {
    const ip = normalizeIp(rawIp);
    if (!isIP(ip) || !remoteIps.has(ip)) continue;
    for (const raw of names.slice(0, 10)) {
      const domain = normalizeDomain(raw);
      const k = `${ip}|${domain}`;
      if (!domain || seen.has(k)) continue;
      seen.add(k);
      rows.push({ agentId, ip, domain, firstSeenAt: at, lastSeenAt: at });
    }
  }
  for (let i = 0; i < rows.length; i += 500) {
    await db
      .insert(ipDomains)
      .values(rows.slice(i, i + 500))
      .onConflictDoUpdate({
        target: [ipDomains.agentId, ipDomains.ip, ipDomains.domain],
        set: { lastSeenAt: sql`greatest(excluded.last_seen_at, ${ipDomains.lastSeenAt})` },
      });
  }
  return rows.length;
}

/** 清單頁用：每個 IP 最近一次被主機解析出的網域（沒有的不在 Map 裡）。 */
export async function localDomainMap(ips: string[]): Promise<Map<string, string>> {
  const uniq = [...new Set(ips.filter(Boolean))];
  if (!uniq.length) return new Map();
  const rows = await getDb()
    .selectDistinctOn([ipDomains.ip], { ip: ipDomains.ip, domain: ipDomains.domain })
    .from(ipDomains)
    .where(inArray(ipDomains.ip, uniq))
    .orderBy(ipDomains.ip, desc(ipDomains.lastSeenAt), ipDomains.domain);
  return new Map(rows.map((r) => [r.ip, r.domain]));
}

/** 保留期限：主機解析過的網域 30 天。 */
export async function pruneLocalDomains(db: DB, now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - LOCAL_RETENTION_DAYS * 86_400_000);
  const r = await db.delete(ipDomains).where(lt(ipDomains.lastSeenAt, cutoff)).returning({ ip: ipDomains.ip });
  return r.length;
}
