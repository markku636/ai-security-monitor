// httpx（JSONL）：只當被動指紋（狀態碼、標題、伺服器、技術、IP）；唯一會產生的問題是「網站沒用 HTTPS」。
import { clip, jsonLines, strings, type NormalizedFinding, type ParseContext, type ParseOutput } from './types';

export const HTTPX_TITLES = {
  noHttps: '網站沒有使用 HTTPS',
} as const;

export function parseHttpx(text: string, ctx: ParseContext): ParseOutput {
  const rows = jsonLines(text, 50);
  const r = rows.find((x) => x.failed !== true) ?? rows[0];
  if (!r) return { findings: [], warnings: ['httpx:no_output'] };
  if (r.failed === true) return { findings: [], warnings: [`httpx:failed:${clip(r.error, 120)}`] };
  const fingerprint = {
    status_code: typeof r.status_code === 'number' ? r.status_code : null,
    title: clip(r.title, 200),
    webserver: clip(r.webserver, 120),
    content_type: clip(r.content_type, 120),
    tech: strings(r.tech, 30, 80),
    ip: clip(r.host, 64),
    cdn: typeof r.cdn_name === 'string' ? clip(r.cdn_name, 60) : null,
    scanned_at: ctx.now.toISOString(),
  };
  const findings: NormalizedFinding[] = [];
  const ok = typeof r.status_code === 'number' && r.status_code < 400;
  if (ctx.scheme === 'http' && ok) {
    findings.push({
      scanner: 'httpx',
      rule: 'web.no_https',
      key: `httpx|web.no_https|${ctx.host}:${ctx.port}`,
      severity: 'medium',
      title: HTTPX_TITLES.noHttps,
      detail: ctx.url,
      recommendation: '申請 TLS 憑證（例如 Let’s Encrypt），把 http 全部轉到 https，並設定 HSTS。',
      location: { url: ctx.url, host: ctx.host, port: ctx.port },
      evidence: { status_code: r.status_code },
      cve: null,
      cwe: ['CWE-319'],
      cvss: null,
      refs: ['https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/'],
      tags: ['owasp-2025:A04'],
    });
  }
  return { findings, fingerprint, warnings: [] };
}
