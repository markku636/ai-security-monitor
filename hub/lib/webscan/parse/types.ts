// 掃描器原始輸出 → 統一的「發現」（欄位仿 OCSF Vulnerability Finding：嚴重度、CVE、CWE、CVSS、位置、證據、參考）。
import type { WebscanScanner } from '../scanners';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];
export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface NormalizedFinding {
  scanner: WebscanScanner;
  /** 規則（`nuclei:<template-id>`、`tls.cert_expired`、`testssl:<id>`）。 */
  rule: string;
  /** 同一個目標內去重用的鍵（掃描器＋規則＋位置）；換成 finding_id 時再加上演算法版本雜湊。 */
  key: string;
  severity: Severity;
  /** Hub 自己產生的發現用繁中原文（顯示時經 t() 翻譯）；工具給的標題（nuclei 模板名）原樣保留。 */
  title: string;
  detail: string;
  recommendation: string;
  location: { url?: string; host?: string; port?: number; param?: string };
  evidence: Record<string, unknown>;
  cve: string | null;
  cwe: string[];
  cvss: number | null;
  refs: string[];
  tags: string[];
}

export interface ParseOutput {
  findings: NormalizedFinding[];
  /** 被動指紋（httpx）：狀態碼、標題、伺服器、技術。 */
  fingerprint?: Record<string, unknown>;
  /** 解析時碰到、但不算問題的狀況（例如 testssl 的 WARN、無法連線）。 */
  warnings: string[];
}

export interface ParseContext {
  url: string;
  host: string;
  port: number;
  scheme: 'http' | 'https';
  now: Date;
}

export const clip = (s: unknown, n: number): string => (typeof s === 'string' ? s : s == null ? '' : String(s)).slice(0, n);

/** JSONL：一行一個物件，壞掉的行略過（最多 5000 行）。 */
export function jsonLines(text: string, max = 5000): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (out.length >= max) break;
    const s = line.trim();
    if (!s.startsWith('{')) continue;
    try {
      const v = JSON.parse(s) as unknown;
      if (v && typeof v === 'object' && !Array.isArray(v)) out.push(v as Record<string, unknown>);
    } catch {
      // 截斷或壞掉的行略過
    }
  }
  return out;
}

export function strings(v: unknown, max = 20, len = 300): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string').slice(0, max).map((x) => x.slice(0, len));
  if (typeof v === 'string' && v) return [v.slice(0, len)];
  return [];
}
