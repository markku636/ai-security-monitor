// 情資來源登錄（repo 根目錄 feeds/registry.json，與 agent 內嵌的是同一份）。
import fs from 'node:fs';
import path from 'node:path';
import { readEnv } from '@/lib/env';

export interface FeedLicense {
  name: string;
  url: string;
  attribution_required: boolean;
  commercial_ok: boolean;
  keep_header?: boolean;
}

export interface FeedEntry {
  id: string;
  name: string;
  vendor: string;
  urls: string[];
  format: string;
  kind: string;
  direction: string;
  confidence: number;
  license: FeedLicense;
  refresh_interval: string;
  requires_api_key: string | null;
  enabled_default: boolean;
  tags: string[];
  notes?: string;
  /** 網域清單的條目是否涵蓋子網域（預設 true）。 */
  match_subdomains?: boolean;
}

/** feeds/ 目錄：`ASA_HUB_FEEDS_DIR` ＞ 開發時的 ../feeds ＞ 容器內的 ./feeds。 */
export function feedsDir(): string | null {
  const candidates = [readEnv('ASA_HUB_FEEDS_DIR') || undefined, path.resolve(process.cwd(), '../feeds'), path.resolve(process.cwd(), 'feeds')];
  for (const c of candidates) {
    if (c && fs.existsSync(path.join(c, 'registry.json'))) return c;
  }
  return null;
}

const g = globalThis as unknown as { __asaRegistry?: { at: number; feeds: FeedEntry[] } };

/** 讀登錄（快取 5 分鐘）；找不到檔案回空陣列。 */
export function loadRegistry(): FeedEntry[] {
  if (g.__asaRegistry && Date.now() - g.__asaRegistry.at < 5 * 60_000) return g.__asaRegistry.feeds;
  const dir = feedsDir();
  let feeds: FeedEntry[] = [];
  if (dir) {
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(dir, 'registry.json'), 'utf8')) as { feeds?: FeedEntry[] };
      feeds = Array.isArray(raw.feeds) ? raw.feeds : [];
    } catch {
      feeds = [];
    }
  }
  g.__asaRegistry = { at: Date.now(), feeds };
  return feeds;
}

/** 頁面分組：威脅指標（IP）、惡意網域與加密 DNS 端點、地理、漏洞、線上查詢（需 API key）。 */
export function feedGroup(f: FeedEntry): 'threat' | 'dns' | 'geo' | 'vuln' | 'lookup' {
  if (f.kind === 'domain' || f.kind === 'doh') return 'dns';
  if (f.kind === 'geo') return 'geo';
  if (f.kind === 'cve') return 'vuln';
  if (f.kind === 'lookup') return 'lookup';
  return 'threat';
}
