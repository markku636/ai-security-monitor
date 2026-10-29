// httpx（JSONL）：被動指紋（狀態碼、標題、伺服器、技術、IP），外加兩個被動檢查：
//   1. 網站沒用 HTTPS（純 http 站台）。
//   2. 缺少建議的安全標頭（CSP、HSTS、X-Content-Type-Options…）；需要 runner 用 `-irh` 擷取回應標頭。
// 標頭值只拿來判斷「有沒有」，不存進 evidence（evidence 只放標頭名稱）；runner 已先遮掉 Set-Cookie 等祕密。
import { clip, jsonLines, strings, type NormalizedFinding, type ParseContext, type ParseOutput } from './types';

export const HTTPX_TITLES = {
  noHttps: '網站沒有使用 HTTPS',
  securityHeaders: '缺少建議的安全標頭',
} as const;

/** httpx 把標頭名稱正規化成小寫底線；建議的安全標頭（HSTS 只在 https 算）。
 * 這是「缺了就該提」的核心集合（低誤報）；像 Cross-Origin-Embedder-Policy、Cross-Origin-Resource-Policy、
 * X-Permitted-Cross-Domain-Policies 這類情境式／舊式標頭刻意不放進來（多數站台沒有也正常，放進來會誤報）。 */
const RECOMMENDED_HEADERS: { key: string; label: string; httpsOnly?: boolean }[] = [
  { key: 'strict_transport_security', label: 'Strict-Transport-Security', httpsOnly: true },
  { key: 'content_security_policy', label: 'Content-Security-Policy' },
  { key: 'x_content_type_options', label: 'X-Content-Type-Options' },
  { key: 'x_frame_options', label: 'X-Frame-Options' },
  { key: 'referrer_policy', label: 'Referrer-Policy' },
  { key: 'permissions_policy', label: 'Permissions-Policy' },
  { key: 'cross_origin_opener_policy', label: 'Cross-Origin-Opener-Policy' },
];
/** 會洩漏技術版本、建議移除的標頭。 */
const DISCLOSURE_HEADERS: { key: string; label: string }[] = [
  { key: 'x_powered_by', label: 'X-Powered-By' },
  { key: 'x_aspnet_version', label: 'X-AspNet-Version' },
  { key: 'x_aspnetmvc_version', label: 'X-AspNetMvc-Version' },
];

const hasHeader = (h: Record<string, unknown>, key: string): boolean => {
  const v = h[key];
  if (Array.isArray(v)) return v.some((x) => typeof x === 'string' && x.trim() !== '');
  return typeof v === 'string' && v.trim() !== '';
};

function noHttpsFinding(ctx: ParseContext, status: number | null): NormalizedFinding | null {
  if (ctx.scheme !== 'http' || status == null || status >= 400) return null;
  return {
    scanner: 'httpx',
    rule: 'web.no_https',
    key: `httpx|web.no_https|${ctx.host}:${ctx.port}`,
    severity: 'medium',
    title: HTTPX_TITLES.noHttps,
    detail: ctx.url,
    recommendation: '申請 TLS 憑證（例如 Let’s Encrypt），把 http 全部轉到 https，並設定 HSTS。',
    location: { url: ctx.url, host: ctx.host, port: ctx.port },
    evidence: { status_code: status },
    cve: null,
    cwe: ['CWE-319'],
    cvss: null,
    refs: ['https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/'],
    tags: ['owasp-2025:A04'],
  };
}

// 安全標頭：只在拿得到回應標頭、而且回傳的是一頁內容（非 3xx 轉址）時判斷——
// runner 不跟轉址，轉址頁（例如首頁 307 到 /tw）本身沒有 body，CSP 之類在落地頁才有意義。
function securityHeadersFinding(r: Record<string, unknown>, ctx: ParseContext, status: number | null): NormalizedFinding | null {
  const header = r.header && typeof r.header === 'object' && !Array.isArray(r.header) ? (r.header as Record<string, unknown>) : null;
  if (!header || status == null || (status >= 300 && status < 400)) return null;
  const missing = RECOMMENDED_HEADERS.filter((h) => !(h.httpsOnly && ctx.scheme !== 'https') && !hasHeader(header, h.key)).map((h) => h.label);
  if (!missing.length) return null;
  const disclosed = DISCLOSURE_HEADERS.filter((h) => hasHeader(header, h.key)).map((h) => h.label);
  return {
    scanner: 'httpx',
    rule: 'web.security_headers',
    key: `httpx|web.security_headers|${ctx.host}:${ctx.port}`,
    severity: 'low',
    title: HTTPX_TITLES.securityHeaders,
    detail: missing.join(', '),
    recommendation: '補上這些建議的安全標頭（Content-Security-Policy、Strict-Transport-Security、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy、Cross-Origin-Opener-Policy）；並移除會洩漏技術版本的 X-Powered-By 等標頭。',
    location: { url: ctx.url, host: ctx.host, port: ctx.port },
    evidence: { missing, disclosed, status_code: status },
    cve: null,
    cwe: ['CWE-693'],
    cvss: null,
    refs: ['https://owasp.org/Top10/2025/A05_2025-Security_Misconfiguration/'],
    tags: ['owasp-2025:A05'],
  };
}

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
    ip: clip(r.host_ip ?? r.host, 64),
    cdn: typeof r.cdn_name === 'string' ? clip(r.cdn_name, 60) : null,
    scanned_at: ctx.now.toISOString(),
  };
  const status = typeof r.status_code === 'number' ? r.status_code : null;
  const findings = [noHttpsFinding(ctx, status), securityHeadersFinding(r, ctx, status)].filter((f): f is NormalizedFinding => f !== null);
  return { findings, fingerprint, warnings: [] };
}
