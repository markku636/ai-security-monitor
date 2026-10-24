// nuclei（JSONL）：每一行一個命中。用 JSONL 而不是 SARIF：JSONL 才帶 classification（CVE、CWE、CVSS、EPSS）。
// 證據只留命中位置、matcher 名稱與截斷過的擷取結果；不存 response（可能含被外洩的密碼、金鑰）。
import { clip, jsonLines, strings, type NormalizedFinding, type ParseContext, type ParseOutput, type Severity } from './types';

const SEV: Record<string, Severity> = { info: 'info', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };

/** 擷取結果遮掉看起來像祕密的值（只留前後幾個字）。 */
export function maskSecret(s: string): string {
  if (s.length < 12) return s;
  return /(key|secret|token|passw|bearer|aws|private)/i.test(s) || /^[A-Za-z0-9+/_=-]{24,}$/.test(s) ? `${s.slice(0, 4)}…${s.slice(-2)}` : s;
}

export function parseNuclei(text: string, ctx: ParseContext): ParseOutput {
  const out: NormalizedFinding[] = [];
  const seen = new Set<string>();
  for (const r of jsonLines(text)) {
    const templateId = clip(r['template-id'], 120);
    if (!templateId) continue;
    const info = (r.info && typeof r.info === 'object' ? r.info : {}) as Record<string, unknown>;
    const cls = (info.classification && typeof info.classification === 'object' ? info.classification : {}) as Record<string, unknown>;
    const matcher = clip(r['matcher-name'], 120);
    const matchedAt = clip(r['matched-at'] ?? r.url ?? r.host, 500);
    const key = `nuclei|${templateId}|${matcher}|${matchedAt}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const cves = strings(cls['cve-id'], 10, 40).map((c) => c.toUpperCase());
    const cwes = strings(cls['cwe-id'], 10, 20).map((c) => c.toUpperCase());
    const score = typeof cls['cvss-score'] === 'number' ? cls['cvss-score'] : null;
    const tags = strings(info.tags, 20, 40);
    out.push({
      scanner: 'nuclei',
      rule: `nuclei:${templateId}`,
      key,
      severity: SEV[String(info.severity ?? '').toLowerCase()] ?? 'info',
      title: clip(info.name, 300) || templateId,
      detail: clip(info.description, 2000),
      recommendation: clip(info.remediation, 2000),
      location: { url: matchedAt, host: ctx.host, port: ctx.port },
      evidence: {
        template: templateId,
        matcher,
        type: clip(r.type, 20),
        extracted: strings(r['extracted-results'], 5, 200).map(maskSecret),
        cvss_metrics: clip(cls['cvss-metrics'], 200),
        epss: typeof cls['epss-score'] === 'number' ? cls['epss-score'] : null,
      },
      cve: cves[0] ?? null,
      cwe: cwes,
      cvss: score,
      refs: strings(info.reference, 10, 500),
      tags: [...tags, ...cves.slice(1)],
    });
  }
  return { findings: out, warnings: [] };
}
