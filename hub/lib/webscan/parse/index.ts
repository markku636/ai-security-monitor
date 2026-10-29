// 依掃描器分派解析；新增掃描器時在這裡加一行，並在 scanners.ts 的登錄表加上它。
import type { WebscanScanner } from '../scanners';
import { parseHttpx } from './httpx';
import { parseNuclei } from './nuclei';
import { parseTestssl } from './testssl';
import { parseTlsx } from './tlsx';
import type { NormalizedFinding, ParseContext, ParseOutput } from './types';

const PARSERS: Record<WebscanScanner, (text: string, ctx: ParseContext) => ParseOutput> = {
  httpx: parseHttpx,
  tlsx: parseTlsx,
  nuclei: parseNuclei,
  testssl: parseTestssl,
};

/**
 * 同一次掃描、兩個掃描器講同一件事時只留一筆：
 * - tlsx 抓到的憑證問題（過期／快到期、名稱不符、自簽）就不再列 testssl 的同類項（tlsx 的標題比較白話）；
 * - httpx 的被動安全標頭檢查（已登錄就會跑、標題白話、把缺的標頭併成一筆）取代 testssl 的 `security_headers`
 *   與 nuclei 的 `http-missing-security-headers` 那堆逐一標頭的 info（nuclei 每個缺的標頭各一筆，很吵）。
 *   這是刻意策展：只以 httpx 檢查的核心建議標頭為準；nuclei 另外會抓的情境式／舊式標頭
 *   （Cross-Origin-Embedder-Policy、Cross-Origin-Resource-Policy、X-Permitted-Cross-Domain-Policies…）
 *   多數站台沒有也正常，故不另外呈現，以免誤報。注意 nuclei 的 `weak-hsts-detect`（HSTS 有、但偏弱）是另一回事，不蓋。
 * 被蓋掉的掃描器其他檢查照留。
 */
const COVERED: Record<string, string[]> = {
  'tls.cert_expired': ['testssl:cert_notAfter', 'testssl:cert_expirationStatus'],
  'tls.cert_expiring': ['testssl:cert_notAfter', 'testssl:cert_expirationStatus'],
  'tls.cert_mismatch': ['testssl:cert_subjectAltName', 'testssl:cert_commonName'],
  'tls.cert_self_signed': ['testssl:cert_trust', 'testssl:cert_chain_of_trust'],
  'web.security_headers': ['testssl:security_headers', 'nuclei:http-missing-security-headers'],
};

export function dedupeAcrossScanners(findings: NormalizedFinding[]): NormalizedFinding[] {
  const drop = new Set(findings.flatMap((f) => COVERED[f.rule] ?? []));
  return drop.size ? findings.filter((f) => !drop.has(f.rule)) : findings;
}

export function parseArtifact(scanner: WebscanScanner, text: string, ctx: ParseContext): ParseOutput {
  try {
    return PARSERS[scanner](text, ctx);
  } catch (e) {
    return { findings: [], warnings: [`${scanner}:parse_error:${e instanceof Error ? e.message.slice(0, 120) : 'unknown'}`] };
  }
}

export type { NormalizedFinding, ParseContext, ParseOutput, Severity } from './types';
