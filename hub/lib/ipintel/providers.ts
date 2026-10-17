// 外部 IP 情資來源：端點、金鑰、額度、快取時間，以及把回應正規化成 Profile 的純函式。
import type { Profile, ProviderId, ProviderPurpose, ProviderResult, SkipReason, UsageType } from './types';

export interface ProviderMeta {
  id: ProviderId;
  name: string;
  purpose: ProviderPurpose;
  key: 'required' | 'optional' | 'none';
  /** 設定金鑰用的環境變數（優先於網頁上存的）。 */
  env: string | null;
  /** 每日呼叫上限（自我節流，避免燒光免費額度）；有金鑰時用 quotaWithKey。 */
  quota: number;
  quotaWithKey?: number;
  ttlMs: number;
  ipv6: boolean;
  /** 給人看的查證頁。 */
  link: ((ip: string) => string) | null;
  signup: string | null;
}

const DAY = 24 * 3600_000;

export const PROVIDERS: ProviderMeta[] = [
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    purpose: 'reputation',
    key: 'required',
    env: 'ASA_HUB_ABUSEIPDB_KEY',
    quota: 1000,
    ttlMs: DAY,
    ipv6: true,
    link: (ip) => `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
    signup: 'https://www.abuseipdb.com/account/api',
  },
  {
    id: 'greynoise',
    name: 'GreyNoise',
    purpose: 'reputation',
    key: 'optional',
    env: 'ASA_HUB_GREYNOISE_KEY',
    quota: 50,
    quotaWithKey: 1000,
    ttlMs: 7 * DAY,
    ipv6: false,
    link: (ip) => `https://viz.greynoise.io/ip/${encodeURIComponent(ip)}`,
    signup: 'https://viz.greynoise.io/signup',
  },
  {
    id: 'ipinfo',
    name: 'IPinfo',
    purpose: 'reputation',
    key: 'required',
    env: 'ASA_HUB_IPINFO_TOKEN',
    quota: 50_000,
    ttlMs: 30 * DAY,
    ipv6: true,
    link: (ip) => `https://ipinfo.io/${encodeURIComponent(ip)}`,
    signup: 'https://ipinfo.io/signup',
  },
  {
    id: 'proxycheck',
    name: 'proxycheck.io',
    purpose: 'reputation',
    key: 'optional',
    env: 'ASA_HUB_PROXYCHECK_KEY',
    quota: 100,
    quotaWithKey: 1000,
    ttlMs: DAY,
    ipv6: true,
    link: (ip) => `https://proxycheck.io/threats/${encodeURIComponent(ip)}`,
    signup: 'https://proxycheck.io/dashboard/',
  },
  {
    id: 'rdns',
    name: 'DNS',
    purpose: 'reputation',
    key: 'none',
    env: null,
    quota: 100_000,
    ttlMs: 7 * DAY,
    ipv6: true,
    link: (ip) => `https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a${encodeURIComponent(ip)}&run=toolpage`,
    signup: null,
  },
  // ---- IP 上的網域（被動 DNS）：只在 IP 分析頁按「查詢網域」才打，不算風險分數、不參與批次查詢 ----
  {
    id: 'hackertarget',
    name: 'HackerTarget',
    purpose: 'domains',
    key: 'optional',
    env: 'ASA_HUB_HACKERTARGET_KEY',
    // 免金鑰的每日次數很少，自己再壓低一點
    quota: 20,
    quotaWithKey: 500,
    ttlMs: 7 * DAY,
    ipv6: false,
    link: (ip) => `https://hackertarget.com/reverse-ip-lookup/?q=${encodeURIComponent(ip)}`,
    signup: 'https://hackertarget.com/scan-membership/',
  },
  {
    id: 'virustotal',
    name: 'VirusTotal',
    purpose: 'domains',
    key: 'required',
    env: 'ASA_HUB_VIRUSTOTAL_KEY',
    quota: 400,
    ttlMs: 7 * DAY,
    ipv6: true,
    link: (ip) => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}/relations`,
    signup: 'https://www.virustotal.com/gui/join-us',
  },
  {
    id: 'otx',
    name: 'AlienVault OTX',
    purpose: 'domains',
    key: 'optional',
    env: 'ASA_HUB_OTX_KEY',
    quota: 100,
    quotaWithKey: 1000,
    ttlMs: 7 * DAY,
    ipv6: true,
    link: (ip) => `https://otx.alienvault.com/indicator/ip/${encodeURIComponent(ip)}`,
    signup: 'https://otx.alienvault.com/accounts/signup',
  },
];

export const REPUTATION_PROVIDERS = PROVIDERS.filter((p) => p.purpose === 'reputation');
export const DOMAIN_PROVIDERS = PROVIDERS.filter((p) => p.purpose === 'domains');

export function providerMeta(id: ProviderId): ProviderMeta {
  return PROVIDERS.find((p) => p.id === id)!;
}

// ---- 正規化 ----

/** AbuseIPDB usageType → 我們的分類；對不到回 null。 */
const ABUSE_USAGE: Record<string, UsageType> = {
  'Data Center/Web Hosting/Transit': 'datacenter',
  'Content Delivery Network': 'datacenter',
  'Search Engine Spider': 'datacenter',
  'Fixed Line ISP': 'isp',
  'Mobile ISP': 'mobile',
  Commercial: 'business',
  Organization: 'business',
  Government: 'gov',
  Military: 'gov',
  'University/College/School': 'edu',
  Library: 'edu',
};

const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);

/** "AS13335" / 13335 → 13335。 */
export function asnNumber(v: unknown): number | null {
  if (typeof v === 'number' && Number.isInteger(v) && v > 0) return v;
  const m = typeof v === 'string' ? /^(?:AS)?(\d{1,10})$/i.exec(v.trim()) : null;
  return m ? Number(m[1]) : null;
}

export function parseAbuseipdb(body: unknown): Profile | null {
  const d = (body as { data?: Record<string, unknown> } | null)?.data;
  if (!d || typeof d !== 'object') return null;
  const score = num(d.abuseConfidenceScore);
  if (score === null) return null;
  const usageRaw = str(d.usageType);
  const usageType = usageRaw ? (ABUSE_USAGE[usageRaw] ?? null) : null;
  return {
    abuseScore: Math.max(0, Math.min(100, Math.round(score))),
    abuseReports: num(d.totalReports) ?? 0,
    abuseLastReportedAt: str(d.lastReportedAt),
    country: str(d.countryCode),
    isp: str(d.isp),
    domain: str(d.domain),
    usageType,
    isDatacenter: usageRaw ? usageType === 'datacenter' : undefined,
    isTor: bool(d.isTor) ?? undefined,
  };
}

export function parseGreynoise(body: unknown): Profile | null {
  const d = body as Record<string, unknown> | null;
  if (!d || typeof d !== 'object') return null;
  return {
    greynoiseClass: str(d.classification) ?? 'unknown',
    greynoiseName: str(d.name),
    greynoiseRiot: bool(d.riot),
  };
}

export function parseIpinfo(body: unknown): Profile | null {
  const d = body as Record<string, unknown> | null;
  if (!d || typeof d !== 'object' || (!d.ip && !d.asn && !d.country_code)) return null;
  return {
    asn: asnNumber(d.asn),
    asnOrg: str(d.as_name),
    domain: str(d.as_domain) ?? undefined,
    country: str(d.country_code),
  };
}

export function parseProxycheck(body: unknown, ip: string): Profile | null {
  const d = body as Record<string, unknown> | null;
  if (!d || typeof d !== 'object') return null;
  const row = (d[ip] ?? Object.values(d).find((v) => v && typeof v === 'object' && 'proxy' in (v as object))) as
    | Record<string, unknown>
    | undefined;
  if (!row || typeof row !== 'object') return null;
  const type = str(row.type);
  const risk = num(typeof row.risk === 'string' ? Number(row.risk) : row.risk);
  return {
    isProxy: row.proxy === 'yes',
    isVpn: type?.toUpperCase() === 'VPN',
    proxyType: type,
    proxyRisk: risk,
    city: str(row.city),
    country: str(row.isocode),
    asn: asnNumber(row.asn) ?? undefined,
    asnOrg: str(row.organisation) ?? str(row.provider) ?? undefined,
  };
}

/** 從組織名／反解主機名猜是不是資料中心（AbuseIPDB 沒給分類時才用）。 */
export function looksLikeDatacenter(...names: (string | null | undefined)[]): boolean | null {
  const text = names.filter(Boolean).join(' ').toLowerCase();
  if (!text) return null;
  const sub = [
    'hosting', 'cloud', 'datacenter', 'data center', 'digitalocean', 'amazon', 'aws', 'google', 'microsoft', 'azure',
    'hetzner', 'linode', 'akamai', 'vultr', 'contabo', 'leaseweb', 'choopa', 'scaleway', 'oracle', 'alibaba', 'tencent',
    'cloudflare', 'fastly', 'ovh',
  ];
  if (sub.some((k) => text.includes(k))) return true;
  // 短字要整個詞才算（"colo" 曾誤中 Colombia）
  if (/\b(colo|colocation|vps|servers?|dedicated)\b/.test(text)) return true;
  return false;
}

// ---- 呼叫 ----

export type FetchFn = typeof fetch;

export interface CallInput {
  ip: string;
  key: string | null;
  fetch: FetchFn;
  timeoutMs: number;
}

type Got = { ok: true; status: number; body: unknown } | { ok: false; reason: SkipReason; detail: string };

async function getJson(f: FetchFn, url: string, headers: Record<string, string>, timeoutMs: number): Promise<Got> {
  try {
    const res = await f(url, { headers: { accept: 'application/json', ...headers }, signal: AbortSignal.timeout(timeoutMs) });
    if (res.status === 429) return { ok: false, reason: 'quota-exhausted', detail: 'HTTP 429' };
    if (!res.ok && res.status !== 404) return { ok: false, reason: 'http-error', detail: `HTTP ${res.status}` };
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      if (res.status !== 404) return { ok: false, reason: 'parse-error', detail: 'invalid JSON' };
    }
    return { ok: true, status: res.status, body };
  } catch (e) {
    const name = e instanceof Error ? e.name : '';
    return { ok: false, reason: name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'http-error', detail: String(e).slice(0, 200) };
  }
}

const now = () => new Date().toISOString();
const fail = (reason: SkipReason, detail?: string): ProviderResult => ({ ok: false, reason, detail, fetchedAt: now() });

export async function callAbuseipdb({ ip, key, fetch: f, timeoutMs }: CallInput): Promise<ProviderResult> {
  if (!key) return fail('no-api-key');
  const g = await getJson(f, `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { Key: key }, timeoutMs);
  if (!g.ok) return fail(g.reason, g.detail);
  if (g.status === 404) return fail('http-error', 'HTTP 404');
  const data = parseAbuseipdb(g.body);
  return data ? { ok: true, fetchedAt: now(), data, raw: g.body } : fail('parse-error');
}

export async function callGreynoise({ ip, key, fetch: f, timeoutMs }: CallInput): Promise<ProviderResult> {
  const g = await getJson(f, `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, key ? { key } : {}, timeoutMs);
  if (!g.ok) return fail(g.reason, g.detail);
  // 404＝GreyNoise 沒看過這個 IP 在網路上掃描（正常結果）
  if (g.status === 404) return { ok: true, fetchedAt: now(), data: { greynoiseClass: 'unknown', greynoiseName: null, greynoiseRiot: false }, raw: g.body };
  const data = parseGreynoise(g.body);
  return data ? { ok: true, fetchedAt: now(), data, raw: g.body } : fail('parse-error');
}

export async function callIpinfo({ ip, key, fetch: f, timeoutMs }: CallInput): Promise<ProviderResult> {
  if (!key) return fail('no-api-key');
  const g = await getJson(f, `https://api.ipinfo.io/lite/${encodeURIComponent(ip)}?token=${encodeURIComponent(key)}`, {}, timeoutMs);
  if (!g.ok) return fail(g.reason, g.detail);
  if (g.status === 404) return fail('http-error', 'HTTP 404');
  const data = parseIpinfo(g.body);
  return data ? { ok: true, fetchedAt: now(), data, raw: g.body } : fail('parse-error');
}

export async function callProxycheck({ ip, key, fetch: f, timeoutMs }: CallInput): Promise<ProviderResult> {
  const qs = `vpn=1&asn=1&risk=1${key ? `&key=${encodeURIComponent(key)}` : ''}`;
  const g = await getJson(f, `https://proxycheck.io/v2/${encodeURIComponent(ip)}?${qs}`, {}, timeoutMs);
  if (!g.ok) return fail(g.reason, g.detail);
  const status = (g.body as { status?: string } | null)?.status;
  if (status === 'denied') return fail('quota-exhausted', (g.body as { message?: string }).message?.slice(0, 200));
  if (status === 'error') return fail('http-error', (g.body as { message?: string }).message?.slice(0, 200));
  const data = parseProxycheck(g.body, ip);
  return data ? { ok: true, fetchedAt: now(), data, raw: g.body } : fail('parse-error');
}

export interface DnsFns {
  reverse: (ip: string) => Promise<string[]>;
  resolve: (host: string) => Promise<string[]>;
}

/** 反解（PTR）＋正反解一致性（FCrDNS）；走 hub 主機自己的 DNS，不經第三方網站。 */
export async function callRdns(ip: string, dns: DnsFns, timeoutMs: number): Promise<ProviderResult> {
  const withTimeout = <T,>(p: Promise<T>) =>
    Promise.race([p, new Promise<never>((_, rej) => setTimeout(() => rej(Object.assign(new Error('timeout'), { name: 'TimeoutError' })), timeoutMs))]);
  try {
    const names = await withTimeout(dns.reverse(ip)).catch((e: NodeJS.ErrnoException) => {
      if (e?.code === 'ENOTFOUND' || e?.code === 'ENODATA') return [] as string[];
      throw e;
    });
    const hostname = names[0]?.replace(/\.$/, '') ?? null;
    let fcrdns: boolean | null = null;
    if (hostname) {
      const addrs = await withTimeout(dns.resolve(hostname)).catch(() => null);
      fcrdns = addrs ? addrs.map((a) => a.toLowerCase()).includes(ip.toLowerCase()) : null;
    }
    return { ok: true, fetchedAt: now(), data: { hostname, fcrdns }, raw: { ptr: names } };
  } catch (e) {
    const timeout = e instanceof Error && e.name === 'TimeoutError';
    return fail(timeout ? 'timeout' : 'http-error', String(e).slice(0, 200));
  }
}
