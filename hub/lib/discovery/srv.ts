// 公司 DNS 要加的 SRV＋TXT 紀錄（電腦端會查 `_ai-security-monitor._tcp.<搜尋網域>`）：從對外網址推出主機／port。
import net from 'node:net';

export const SRV_SERVICE = '_ai-security-monitor._tcp';
export const PLACEHOLDER_DOMAIN = 'corp.example';

export interface SrvInfo {
  name: string;
  domain: string;
  target: string;
  port: number;
  txt: string[];
  /** 對外網址是 IP／單一名稱，網域是範例值，要換成公司的網域。 */
  placeholder: boolean;
}

export function srvInfo(publicUrl: string | null, fingerprint: string): SrvInfo | null {
  if (!publicUrl) return null;
  let u: URL;
  try {
    u = new URL(publicUrl);
  } catch {
    return null;
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
  const labels = host.split('.');
  const isName = !net.isIP(host) && labels.length >= 3;
  const domain = isName ? labels.slice(1).join('.') : PLACEHOLDER_DOMAIN;
  const target = net.isIP(host) || labels.length < 2 ? `hub.${PLACEHOLDER_DOMAIN}` : host;
  return {
    name: `${SRV_SERVICE}.${domain}`,
    domain,
    target,
    port,
    txt: [`url=${publicUrl}`, `fp=${fingerprint}`],
    placeholder: !isName,
  };
}

/** Windows DNS Server（PowerShell）與 BIND zone 檔的寫法。 */
export function srvCommands(s: SrvInfo): { windows: string; bind: string } {
  const txt = s.txt.map((x) => `"${x}"`).join(' ');
  return {
    windows: [
      `Add-DnsServerResourceRecord -ZoneName ${s.domain} -Name ${SRV_SERVICE} -Srv -DomainName ${s.target} -Port ${s.port} -Priority 0 -Weight 0`,
      // -DescriptiveText 只收一個字串：每個 key=value 各加一筆 TXT
      ...s.txt.map((x) => `Add-DnsServerResourceRecord -ZoneName ${s.domain} -Name ${SRV_SERVICE} -Txt -DescriptiveText '${x}'`),
    ].join('\n'),
    bind: [`${s.name}. 3600 IN SRV 0 0 ${s.port} ${s.target}.`, `${s.name}. 3600 IN TXT ${txt}`].join('\n'),
  };
}
