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
 * 同一次掃描、兩個掃描器講同一件事時只留一筆：tlsx 已經抓到的憑證問題（過期／快到期、名稱不符、自簽）
 * 就不再列 testssl 的同類項目（tlsx 的標題比較白話；testssl 其他的 TLS 檢查照留）。
 */
const COVERED_BY_TLSX: Record<string, string[]> = {
  'tls.cert_expired': ['testssl:cert_notAfter', 'testssl:cert_expirationStatus'],
  'tls.cert_expiring': ['testssl:cert_notAfter', 'testssl:cert_expirationStatus'],
  'tls.cert_mismatch': ['testssl:cert_subjectAltName', 'testssl:cert_commonName'],
  'tls.cert_self_signed': ['testssl:cert_trust', 'testssl:cert_chain_of_trust'],
};

export function dedupeAcrossScanners(findings: NormalizedFinding[]): NormalizedFinding[] {
  const drop = new Set(findings.flatMap((f) => COVERED_BY_TLSX[f.rule] ?? []));
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
