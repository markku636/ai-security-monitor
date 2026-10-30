// 網站掃描的範圍與 SSRF 防護（Hub 端；runner 端在 agent/src/webscan/scope.rs 再檢查一次）。
//
// 原則：Hub 本身永遠不連線到掃描目標，只做 DNS 解析；建立掃描工作時把「解析後、通過檢查」的位址釘進工作內容，
// runner 只准連那些位址（DNS 之後換掉也打不到別處，擋 DNS rebinding）。
//   永遠禁止：loopback、link-local、雲端 metadata、multicast、保留／文件用網段、內嵌 IPv4 的轉譯網段、Hub 自己的位址
//   私有網段（10/8、172.16/12、192.168/16、100.64/10、fc00::/7）：只有落在管理員設定的內網網段白名單內才放行
import dns from 'node:dns';
import net from 'node:net';
import os from 'node:os';
import { matchCidr } from '@/lib/enroll/cidr';
import { normalizeIp } from '@/lib/ipintel/ip';

export const MAX_URL_LENGTH = 2048;
const RESOLVE_TIMEOUT_MS = 5_000;
const MAX_ADDRS = 16;

export type ScreenReason =
  | 'invalid_ip'
  | 'unresolvable'
  | 'forbidden_host'
  | 'metadata'
  | 'self'
  | 'unspecified'
  | 'loopback'
  | 'link_local'
  | 'multicast'
  | 'reserved'
  | 'private_not_allowed';

export type ScreenResult = { ok: true; ips: string[]; internal: boolean } | { ok: false; reason: ScreenReason; ip?: string };

function list(entries: ReadonlyArray<readonly [string, number]>, family: 'ipv4' | 'ipv6', into = new net.BlockList()): net.BlockList {
  for (const [addr, bits] of entries) into.addSubnet(addr, bits, family);
  return into;
}

const METADATA_V4 = list([['169.254.169.254', 32], ['169.254.170.2', 32], ['100.100.100.200', 32]], 'ipv4');
const METADATA = list([['fd00:ec2::254', 128]], 'ipv6', METADATA_V4);

const UNSPECIFIED = list([['::', 128]], 'ipv6', list([['0.0.0.0', 8]], 'ipv4'));
const LOOPBACK = list([['::1', 128]], 'ipv6', list([['127.0.0.0', 8]], 'ipv4'));
const LINK_LOCAL = list([['fe80::', 10]], 'ipv6', list([['169.254.0.0', 16]], 'ipv4'));
const MULTICAST = list([['ff00::', 8]], 'ipv6', list([['224.0.0.0', 4]], 'ipv4'));
const RESERVED = list(
  [
    ['100::', 64], // discard
    ['2001:db8::', 32], // 文件用
    ['2001::', 32], // Teredo（內嵌 IPv4）
    ['2002::', 16], // 6to4（內嵌 IPv4，可能繞到 127.0.0.1）
    ['64:ff9b::', 96], // NAT64（同上）
    ['64:ff9b:1::', 48],
  ],
  'ipv6',
  list(
    [
      ['192.0.0.0', 24],
      ['192.0.2.0', 24],
      ['192.88.99.0', 24],
      ['198.18.0.0', 15],
      ['198.51.100.0', 24],
      ['203.0.113.0', 24],
      ['240.0.0.0', 4],
    ],
    'ipv4',
  ),
);
const PRIVATE = list([['fc00::', 7]], 'ipv6', list([['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10]], 'ipv4'));

/** 不准拿來當掃描目標的名稱（本機、雲端 metadata、compose 內部服務）。 */
const FORBIDDEN_NAMES = new Set(['localhost', 'metadata', 'metadata.google.internal', 'instance-data', 'instance-data.ec2.internal', 'hub', 'postgres', 'webscan', 'zap']);

export function forbiddenHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return FORBIDDEN_NAMES.has(h) || h.endsWith('.localhost') || (h.startsWith('metadata.') && h.endsWith('.internal'));
}

export interface ParsedTarget {
  url: string;
  scheme: 'http' | 'https';
  host: string;
  port: number;
  path: string;
}

type UrlError = 'bad_url' | 'bad_scheme' | 'url_credentials' | 'forbidden_host' | 'url_too_long';

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9-]{1,63}$/;

function cleanHost(hostname: string): string {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  return h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
}

function defaultPort(scheme: 'http' | 'https'): number {
  return scheme === 'https' ? 443 : 80;
}

/** 輸入字串的粗檢（長度、空白與引號這類不該出現在網址裡的字元）→ 加上預設 scheme 的 URL。 */
function toUrl(raw: string): URL | { error: UrlError } {
  const s = String(raw ?? '').trim();
  if (!s) return { error: 'bad_url' };
  if (s.length > MAX_URL_LENGTH) return { error: 'url_too_long' };
  if (/[\s<>"'`\\]/.test(s)) return { error: 'bad_url' };
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
  } catch {
    return { error: 'bad_url' };
  }
}

/** 使用者輸入的網址 → 正規化的目標；沒寫 scheme 就當 https。不合法回錯誤碼。 */
export function parseTargetUrl(raw: string): ParsedTarget | { error: UrlError } {
  const u = toUrl(raw);
  if (!(u instanceof URL)) return u;
  const scheme = u.protocol.replace(/:$/, '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') return { error: 'bad_scheme' };
  if (u.username || u.password) return { error: 'url_credentials' };
  const host = cleanHost(u.hostname);
  if (!host || (!net.isIP(host) && !HOST_RE.test(host))) return { error: 'bad_url' };
  if (forbiddenHost(host)) return { error: 'forbidden_host' };
  const port = u.port ? Number(u.port) : defaultPort(scheme);
  if (port < 1) return { error: 'bad_url' };
  const path = (u.pathname || '/').slice(0, 512) || '/';
  const hostPart = net.isIPv6(host) ? `[${host}]` : host;
  const portPart = port === defaultPort(scheme) ? '' : `:${port}`;
  return { url: `${scheme}://${hostPart}${portPart}${path}`, scheme, host, port, path };
}

function family(ip: string): 'ipv4' | 'ipv6' {
  return net.isIPv4(ip) ? 'ipv4' : 'ipv6';
}

/** 一個位址的分類（不看白名單）：回 null＝公網。 */
export function classifyIp(raw: string): Exclude<ScreenReason, 'unresolvable' | 'forbidden_host' | 'self' | 'private_not_allowed'> | 'private' | null {
  const ip = normalizeIp(raw);
  if (!net.isIP(ip)) return 'invalid_ip';
  const f = family(ip);
  if (METADATA.check(ip, f)) return 'metadata';
  if (UNSPECIFIED.check(ip, f)) return 'unspecified';
  if (LOOPBACK.check(ip, f)) return 'loopback';
  if (LINK_LOCAL.check(ip, f)) return 'link_local';
  if (MULTICAST.check(ip, f)) return 'multicast';
  if (RESERVED.check(ip, f)) return 'reserved';
  if (PRIVATE.check(ip, f)) return 'private';
  return null;
}

export interface ScreenOpts {
  /** 管理員設定的內網網段白名單（已正規化的 CIDR）。 */
  internalCidrs: string[];
  /** 掃描端或 Hub 自己的位址：永遠禁止。 */
  selfIps?: string[];
}

/** 一組位址全部都要通過；任何一個不過就整組不准（不挑「可以的那個」）。 */
export function screenIps(ips: string[], opts: ScreenOpts): ScreenResult {
  if (!ips.length) return { ok: false, reason: 'unresolvable' };
  const self = new Set((opts.selfIps ?? []).map((s) => normalizeIp(s)));
  const out: string[] = [];
  let internal = false;
  for (const raw of ips) {
    const ip = normalizeIp(raw);
    const c = classifyIp(ip);
    if (c && c !== 'private') return { ok: false, reason: c, ip };
    if (self.has(ip)) return { ok: false, reason: 'self', ip };
    if (c === 'private') {
      if (!matchCidr(ip, opts.internalCidrs)) return { ok: false, reason: 'private_not_allowed', ip };
      internal = true;
    }
    if (!out.includes(ip)) out.push(ip);
  }
  return { ok: true, ips: out, internal };
}

type Lookup = (host: string) => Promise<string[]>;

const g = globalThis as unknown as { __asaWebscanLookup?: Lookup; __asaSelfIps?: { at: number; ips: string[] } };

async function systemLookup(host: string): Promise<string[]> {
  const rows = await dns.promises.lookup(host, { all: true, verbatim: true });
  return rows.map((r) => r.address);
}

/** 測試用：換掉 DNS 解析（null＝還原）。 */
export function setWebscanLookupForTests(fn: Lookup | null): void {
  g.__asaWebscanLookup = fn ?? undefined;
}

export function setSelfIpsForTests(ips: string[] | null): void {
  g.__asaSelfIps = ips ? { at: Number.MAX_SAFE_INTEGER, ips } : undefined;
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([p, new Promise<T>((_, reject) => setTimeout(() => reject(new Error('timeout')), ms).unref?.())]);
}

/** 名稱 → 位址（IP 字面值直接回傳）；查不到回空陣列。 */
export async function resolveHost(host: string): Promise<string[]> {
  if (net.isIP(host)) return [normalizeIp(host)];
  try {
    const addrs = await withTimeout((g.__asaWebscanLookup ?? systemLookup)(host), RESOLVE_TIMEOUT_MS);
    return [...new Set(addrs.map(normalizeIp))].slice(0, MAX_ADDRS);
  } catch {
    return [];
  }
}

/** Hub 這台（容器）自己的網卡位址，快取一分鐘。 */
export function hubSelfIps(now = Date.now()): string[] {
  const c = g.__asaSelfIps;
  if (c && now - c.at < 60_000) return c.ips;
  const ips = Object.values(os.networkInterfaces())
    .flat()
    .filter((a): a is os.NetworkInterfaceInfo => !!a)
    .map((a) => normalizeIp(a.address.split('%')[0] ?? a.address));
  g.__asaSelfIps = { at: now, ips };
  return ips;
}

/** 解析＋檢查：建立掃描工作時用，回傳要釘進工作的位址。 */
export async function resolveAndScreen(host: string, opts: ScreenOpts): Promise<ScreenResult> {
  if (forbiddenHost(host)) return { ok: false, reason: 'forbidden_host' };
  const ips = await resolveHost(host);
  if (!ips.length) return { ok: false, reason: 'unresolvable' };
  return screenIps(ips, { ...opts, selfIps: [...(opts.selfIps ?? []), ...hubSelfIps()] });
}
