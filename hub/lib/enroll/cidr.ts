// 自動核准網段（CIDR）：解析、正規化、比對（node:net BlockList）。
import net from 'node:net';
import { normalizeIp } from '@/lib/http';

export const MIN_PREFIX = { 4: 8, 6: 16 } as const;
export const MAX_CIDRS = 64;

export type CidrError = { error: 'bad_cidr' | 'cidr_too_broad'; value: string };

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((n, p) => n * 256 + Number(p), 0);
}

function intToIpv4(n: number): string {
  return [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.');
}

function ipv6ToBig(ip: string): bigint {
  const [head, tail] = ip.includes('::') ? ip.split('::') : [ip, undefined];
  const parse = (s: string | undefined) => (s ? s.split(':') : []);
  let left = parse(head);
  let right = parse(tail);
  // 尾端是內嵌 IPv4（::ffff:1.2.3.4）
  const fix = (arr: string[]) => {
    const last = arr[arr.length - 1];
    if (last && last.includes('.')) {
      const n = ipv4ToInt(last);
      return [...arr.slice(0, -1), (Math.floor(n / 65536)).toString(16), (n % 65536).toString(16)];
    }
    return arr;
  };
  left = fix(left);
  right = fix(right);
  const fill = tail === undefined ? [] : new Array(8 - left.length - right.length).fill('0');
  const parts = [...left, ...fill, ...right];
  return parts.reduce((n, p) => (n << 16n) + BigInt(parseInt(p || '0', 16)), 0n);
}

function bigToIpv6(n: bigint): string {
  const parts: string[] = [];
  for (let i = 7; i >= 0; i--) parts.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  // 最長一段連續 0 壓成 ::
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (parts[i] !== '0') {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && parts[j] === '0') j++;
    if (j - i > bestLen && j - i > 1) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (best < 0) return parts.join(':');
  return `${parts.slice(0, best).join(':')}::${parts.slice(best + bestLen).join(':')}`;
}

/** 一筆 CIDR → 正規化字串（網路位址＋前綴；單一 IP → /32、/128），或錯誤。 */
export function normalizeCidr(input: string): string | CidrError {
  const value = String(input ?? '').trim();
  if (!value || value.length > 64) return { error: 'bad_cidr', value };
  const slash = value.indexOf('/');
  const ipPart = normalizeIp(slash >= 0 ? value.slice(0, slash) : value);
  const v = net.isIP(ipPart);
  if (!v) return { error: 'bad_cidr', value };
  const max = v === 4 ? 32 : 128;
  let prefix = max;
  if (slash >= 0) {
    const p = value.slice(slash + 1);
    if (!/^\d{1,3}$/.test(p)) return { error: 'bad_cidr', value };
    prefix = Number(p);
    if (prefix > max) return { error: 'bad_cidr', value };
  }
  if (prefix < MIN_PREFIX[v as 4 | 6]) return { error: 'cidr_too_broad', value };
  if (v === 4) {
    const n = ipv4ToInt(ipPart);
    const size = 2 ** (32 - prefix);
    return `${intToIpv4(Math.floor(n / size) * size)}/${prefix}`;
  }
  const big = ipv6ToBig(ipPart.toLowerCase());
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix);
  return `${bigToIpv6(big & mask)}/${prefix}`;
}

/** 整份清單：去重、保留順序；任何一筆不合法就回第一個錯誤。 */
export function normalizeCidrList(list: unknown): string[] | CidrError {
  if (!Array.isArray(list)) return { error: 'bad_cidr', value: '' };
  const out: string[] = [];
  for (const x of list) {
    if (typeof x !== 'string') return { error: 'bad_cidr', value: String(x) };
    if (!x.trim()) continue;
    const r = normalizeCidr(x);
    if (typeof r !== 'string') return r;
    if (!out.includes(r)) out.push(r);
  }
  return out;
}

/** ip 落在哪一個 CIDR（回第一個符合的），都不符合 → null。 */
export function matchCidr(ip: string | null, cidrs: string[]): string | null {
  if (!ip) return null;
  const addr = normalizeIp(ip);
  const v = net.isIP(addr);
  if (!v) return null;
  for (const c of cidrs) {
    const [net0, p] = c.split('/');
    const cv = net.isIP(net0);
    if (cv !== v) continue;
    const bl = new net.BlockList();
    try {
      bl.addSubnet(net0, Number(p), v === 4 ? 'ipv4' : 'ipv6');
      if (bl.check(addr, v === 4 ? 'ipv4' : 'ipv6')) return c;
    } catch {
      // 壞掉的設定值略過
    }
  }
  return null;
}
