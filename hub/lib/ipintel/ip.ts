// 判斷是不是公網 IP：私有、保留、文件用、多播等網段不查外部情資（查了也沒意義，還會洩漏內網位址）。
import { BlockList, isIP } from 'node:net';

const reserved = new BlockList();
for (const [net, bits] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  reserved.addSubnet(net, bits, 'ipv4');
}
for (const [net, bits] of [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  reserved.addSubnet(net, bits, 'ipv6');
}

/** IPv4-mapped IPv6（::ffff:1.2.3.4）轉回 IPv4。 */
export function normalizeIp(s: string): string {
  const v = s.trim();
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(v);
  return m ? m[1] : v.toLowerCase();
}

export function isPublicIp(s: string): boolean {
  const ip = normalizeIp(s);
  const fam = isIP(ip);
  if (!fam) return false;
  return !reserved.check(ip, fam === 4 ? 'ipv4' : 'ipv6');
}
