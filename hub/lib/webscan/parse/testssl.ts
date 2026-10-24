// testssl.sh（--jsonfile，扁平陣列）：LOW 以上算問題；WARN／FATAL 是掃描本身的狀況（記成警告）；OK／INFO 略過。
import { clip, type NormalizedFinding, type ParseContext, type ParseOutput, type Severity } from './types';

const SEV: Record<string, Severity> = { LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' };

/** 常見項目的白話標題（繁中原文，顯示時翻譯）；其他項目用不翻譯的「testssl: <id>」。 */
export const TESTSSL_TITLES: Record<string, string> = {
  SSLv2: '伺服器還提供 SSLv2',
  SSLv3: '伺服器還提供 SSLv3',
  TLS1: '伺服器還提供 TLS 1.0',
  TLS1_1: '伺服器還提供 TLS 1.1',
  HSTS: '沒有設定 HSTS',
  cert_expirationStatus: '網站憑證已過期或快到期',
  cert_chain_of_trust: '憑證鏈不受信任',
  BREACH: '可能受 BREACH 攻擊影響（HTTP 壓縮）',
  POODLE_SSL: '可能受 POODLE 攻擊影響',
  heartbleed: '可能受 Heartbleed 漏洞影響',
  ROBOT: '可能受 ROBOT 攻擊影響',
  SWEET32: '可能受 SWEET32 攻擊影響（64 位元區塊加密）',
  LOGJAM: '可能受 Logjam 攻擊影響（弱 DH 參數）',
  FREAK: '可能受 FREAK 攻擊影響',
  DROWN: '可能受 DROWN 攻擊影響',
  LUCKY13: '可能受 Lucky13 攻擊影響',
  RC4: '伺服器還提供 RC4 加密',
  cipherlist_NULL: '伺服器提供不加密的 NULL 加密套件',
  cipherlist_aNULL: '伺服器提供沒有身分驗證的加密套件',
  cipherlist_EXPORT: '伺服器提供出口等級的弱加密套件',
  cipherlist_LOW: '伺服器提供弱加密套件',
  cipherlist_3DES_IDEA: '伺服器提供 3DES／IDEA 加密套件',
  secure_renego: '不支援安全重新協商',
  secure_client_renego: '允許用戶端發起的重新協商',
};

/** 沒有白話標題的項目：不翻譯的中性標題（存進資料庫的標題不能帶插值，否則顯示時查不到譯文）。 */
const genericTitle = (id: string) => `testssl: ${id}`;

type Item = Record<string, unknown>;

/** 扁平格式直接是陣列；--jsonfile-pretty 是 { scanResult: [ { …, <分類>: [項目] } ] }。 */
function flatten(rows: unknown): Item[] {
  if (Array.isArray(rows)) return rows as Item[];
  const sr = (rows as { scanResult?: unknown } | null)?.scanResult;
  if (!Array.isArray(sr)) return [];
  return (sr as Item[]).flatMap((s) => Object.values(s).filter(Array.isArray).flat()) as Item[];
}

const ids = (s: string, re: RegExp) => s.split(/\s+/).filter((c) => re.test(c)).map((c) => c.toUpperCase());

function toFinding(it: Item, id: string, severity: Severity, port: number, ctx: ParseContext): NormalizedFinding {
  const cves = ids(clip(it.cve, 300), /^CVE-\d{4}-\d+$/i);
  return {
    scanner: 'testssl',
    rule: `testssl:${id}`,
    key: `testssl|${id}|${port}`,
    severity,
    title: TESTSSL_TITLES[id] ?? genericTitle(id),
    detail: clip(it.finding, 1000),
    recommendation: '',
    location: { url: ctx.url, host: ctx.host, port },
    evidence: { id, finding: clip(it.finding, 500), ip: clip(it.ip, 120) },
    cve: cves[0] ?? null,
    cwe: ids(clip(it.cwe, 100), /^CWE-\d+$/i),
    cvss: null,
    refs: cves.map((c) => `https://nvd.nist.gov/vuln/detail/${c}`),
    tags: ['tls', 'owasp-2025:A04'],
  };
}

export function parseTestssl(text: string, ctx: ParseContext): ParseOutput {
  let rows: unknown;
  try {
    rows = JSON.parse(text);
  } catch {
    return { findings: [], warnings: ['testssl:bad_json'] };
  }
  const out = new Map<string, NormalizedFinding>();
  const warnings: string[] = [];
  for (const it of flatten(rows).slice(0, 2000)) {
    if (!it || typeof it !== 'object') continue;
    const id = clip(it.id, 80);
    const level = String(it.severity ?? '').toUpperCase();
    if ((level === 'WARN' || level === 'FATAL') && warnings.length < 20) warnings.push(`testssl:${level.toLowerCase()}:${id}:${clip(it.finding, 120)}`);
    const severity = SEV[level];
    if (!id || !severity) continue;
    const f = toFinding(it, id, severity, Number(it.port) || ctx.port, ctx);
    if (!out.has(f.key)) out.set(f.key, f);
  }
  return { findings: [...out.values()], warnings };
}
