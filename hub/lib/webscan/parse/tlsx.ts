// tlsx（JSONL）：憑證過期／快到期、自簽、名稱不符、協商到過時的 TLS 版本。
// 「名稱不符」不用 tlsx 的 mismatched：runner 為了釘 IP 是用 `-u <IP>:<port> -sni <host>` 連，tlsx 會拿 IP 去比對憑證，
// 每個網域憑證都會被判成不符；改由這裡用憑證的 CN／SAN 對目標的主機名稱判斷。
import net from 'node:net';
import { clip, jsonLines, strings, type NormalizedFinding, type ParseContext, type ParseOutput, type Severity } from './types';

/** 憑證名稱（CN、SAN）有沒有涵蓋這個主機；`*.example.com` 只涵蓋一層（`a.example.com`，不含 `a.b.example.com` 與 IP）。 */
export function certCovers(host: string, names: string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return names.some((raw) => {
    const n = raw.toLowerCase().trim().replace(/\.$/, '');
    if (!n) return false;
    if (n === h) return true;
    if (!n.startsWith('*.') || net.isIP(h)) return false;
    const dot = h.indexOf('.');
    return dot > 0 && h.slice(dot + 1) === n.slice(2);
  });
}

export const TLSX_TITLES = {
  expired: '網站憑證已過期',
  expiring: '網站憑證即將到期',
  selfSigned: '網站使用自簽憑證',
  mismatched: '憑證上的名稱跟網址不符',
  oldTls: '連線協商到過時的 TLS 版本',
} as const;

const OLD_TLS = new Set(['tls10', 'tls11', 'ssl30', 'sslv3']);

export function parseTlsx(text: string, ctx: ParseContext): ParseOutput {
  const rows = jsonLines(text, 20);
  const r = rows.find((x) => x.probe_status !== false) ?? rows[0];
  if (!r) return { findings: [], warnings: ['tlsx:no_output'] };
  if (r.probe_status === false) return { findings: [], warnings: [`tlsx:failed:${clip(r.error, 120)}`] };
  const loc = { url: ctx.url, host: ctx.host, port: ctx.port };
  const evidence = {
    subject_cn: clip(r.subject_cn, 200),
    subject_an: strings(r.subject_an, 20, 200),
    issuer_cn: clip(r.issuer_cn, 200),
    not_after: clip(r.not_after, 40),
    tls_version: clip(r.tls_version, 20),
    cipher: clip(r.cipher, 80),
  };
  const out: NormalizedFinding[] = [];
  const add = (rule: string, severity: Severity, title: string, detail: string, recommendation: string, cwe: string[]) =>
    out.push({ scanner: 'tlsx', rule, key: `tlsx|${rule}|${ctx.host}:${ctx.port}`, severity, title, detail, recommendation, location: loc, evidence, cve: null, cwe, cvss: null, refs: [], tags: ['owasp-2025:A04'] });
  const notAfter = typeof r.not_after === 'string' ? Date.parse(r.not_after) : NaN;
  const days = Number.isFinite(notAfter) ? Math.floor((notAfter - ctx.now.getTime()) / 86_400_000) : null;
  if (r.expired === true || (days != null && days < 0)) {
    add('tls.cert_expired', 'high', TLSX_TITLES.expired, evidence.not_after, '立刻更新憑證；瀏覽器會擋下過期憑證的網站。', ['CWE-298']);
  } else if (days != null && days <= 30) {
    add('tls.cert_expiring', days <= 7 ? 'high' : 'medium', TLSX_TITLES.expiring, `${evidence.not_after}（${days}d）`, '在到期前更新憑證，建議改成自動續約。', ['CWE-298']);
  }
  if (r.self_signed === true) add('tls.cert_self_signed', 'medium', TLSX_TITLES.selfSigned, evidence.issuer_cn, '改用公開信任的憑證機構簽發的憑證。', ['CWE-295']);
  const names = [evidence.subject_cn, ...evidence.subject_an].filter(Boolean);
  if (names.length && !certCovers(ctx.host, names)) add('tls.cert_mismatch', 'high', TLSX_TITLES.mismatched, names.join(', '), '換一張包含這個網域名稱的憑證。', ['CWE-297']);
  if (OLD_TLS.has(String(r.tls_version ?? '').toLowerCase())) {
    add('tls.old_protocol', 'medium', TLSX_TITLES.oldTls, evidence.tls_version, '在伺服器關掉 TLS 1.0／1.1，只留 TLS 1.2 以上。', ['CWE-327']);
  }
  return { findings: out, warnings: [] };
}
