// 情資鏡像：hub 依 feeds/registry.json 從各廠商下載清單存在本機，agent 改從 hub 拿（省得每台都去打廠商）。
// 原檔原樣保存（保留檔頭與授權標註），解析交給 agent；hub 只記抓取時間、大小、sha256、大概條目數。
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { hasScope, type Identity } from '@/lib/auth/access';
import { loadRegistry, type FeedEntry } from './registry';
import { getDb } from '@/lib/db';
import { readEnv } from '@/lib/env';
import { allowNoncommercial } from './usage';

const MAX_BYTES = 96 * 1024 * 1024;
const CONCURRENCY = 4;
const TIMEOUT_MS = 120_000;
const DATA_FILE = 'latest';
const META_FILE = 'meta.json';

export interface MirrorMeta {
  feed_id: string;
  status: 'ok' | 'error';
  url: string | null;
  etag: string | null;
  last_modified: string | null;
  fetched_at: string | null;
  checked_at: string | null;
  bytes: number;
  sha256: string | null;
  /** 文字格式的非註解行數（JSON／mmdb 為 null）。 */
  entries: number | null;
  error: string | null;
}

export interface SyncOutcome {
  feed_id: string;
  status: 'updated' | 'not_modified' | 'fresh' | 'error';
  bytes: number;
  ms: number;
  detail?: string;
}

/** 快取目錄：`ASA_HUB_FEED_CACHE_DIR` ＞ 容器的 /data/feeds ＞ 開發時的 .data/feeds。 */
export function cacheDir(): string {
  const dir = readEnv('ASA_HUB_FEED_CACHE_DIR');
  if (dir) return dir;
  if (fs.existsSync('/data') && process.platform !== 'win32') return '/data/feeds';
  return path.resolve(process.cwd(), '.data', 'feeds');
}

function feedPath(id: string, file: string): string {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) throw new Error('bad feed id');
  return path.join(cacheDir(), id, file);
}

/** 誰能拿鏡像：agent（client 金鑰）、admin、read token；公開檢視不行（原檔是各廠商的授權內容，不對外再散布）。 */
export function mirrorAllowed(id: Identity): boolean {
  return id.role === 'client' || id.role === 'admin' || hasScope(id, 'read') || hasScope(id, 'dns');
}

/**
 * 只有能整份下載的清單才鏡像（即時查詢 API 不算）；依登錄的預設啟用。
 * 只限非商業用途的來源要 Hub 設成「個人／非商業用途」（`noncommercial`，見 lib/intel/usage.ts）才鏡像。
 */
export function mirrorable(f: FeedEntry, noncommercial = false): boolean {
  return f.enabled_default && f.urls.length > 0 && f.format !== 'lookup-api' && f.kind !== 'lookup' && (f.license.commercial_ok || noncommercial);
}

export function readMeta(id: string): MirrorMeta | null {
  try {
    return JSON.parse(fs.readFileSync(feedPath(id, META_FILE), 'utf8')) as MirrorMeta;
  } catch {
    return null;
  }
}

/** 原檔路徑（沒有資料回 null）。 */
export function dataPath(id: string): string | null {
  const p = feedPath(id, DATA_FILE);
  return fs.existsSync(p) ? p : null;
}

function writeAtomic(file: string, data: Buffer | string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

/** "30m" / "1h" / "24h" / "720h" / "1d" → 毫秒（看不懂就 1 小時）。 */
export function refreshMs(s: string): number {
  const m = /^(\d+)\s*([smhd])$/.exec(s.trim());
  if (!m) return 3_600_000;
  const n = Number(m[1]);
  return n * { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as 's' | 'm' | 'h' | 'd'];
}

/** `{YYYY}-{MM}` 範本：先試本月再試上個月（DB-IP 月初才發布）；與 agent 的 expand_urls 相同。 */
export function expandUrls(tpl: string, now = new Date()): string[] {
  if (!tpl.includes('{YYYY}')) return [tpl];
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth() + 1;
  const prev = m === 1 ? [y - 1, 12] : [y, m - 1];
  return [[y, m], prev].map(([yy, mm]) => tpl.replace('{YYYY}', String(yy).padStart(4, '0')).replace('{MM}', String(mm).padStart(2, '0')));
}

function isFresh(f: FeedEntry, m: MirrorMeta | null, now: number): boolean {
  const last = m?.checked_at ?? m?.fetched_at;
  if (!m?.sha256 || !last) return false;
  return now - Date.parse(last) < refreshMs(f.refresh_interval);
}

function countEntries(format: string, body: Buffer): number | null {
  if (format.includes('json') || format.startsWith('mmdb')) return null;
  let n = 0;
  for (const line of body.toString('utf8').split('\n')) {
    const s = line.trim();
    if (s && !s.startsWith('#') && !s.startsWith(';')) n += 1;
  }
  return n;
}

async function readCapped(res: Response): Promise<Buffer> {
  const len = Number(res.headers.get('content-length') ?? 0);
  if (len > MAX_BYTES) throw new Error('too large');
  if (!res.body) return Buffer.alloc(0);
  const chunks: Buffer[] = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BYTES) {
      await reader.cancel();
      throw new Error('too large');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

type FetchFn = typeof fetch;

async function fetchOne(f: FeedEntry, prev: MirrorMeta | null, fetchImpl: FetchFn, version: string): Promise<SyncOutcome> {
  const started = Date.now();
  const now = new Date();
  const meta: MirrorMeta = prev ?? { feed_id: f.id, status: 'ok', url: null, etag: null, last_modified: null, fetched_at: null, checked_at: null, bytes: 0, sha256: null, entries: null, error: null };
  meta.checked_at = now.toISOString();
  let lastErr = 'no url';
  for (const url of expandUrls(f.urls[0], now)) {
    const headers: Record<string, string> = { 'user-agent': `asa-hub/${version} (+https://github.com/markku636/ai-security-monitor)` };
    if (prev?.sha256 && prev.url === url) {
      if (prev.etag) headers['if-none-match'] = prev.etag;
      if (prev.last_modified) headers['if-modified-since'] = prev.last_modified;
    }
    try {
      const res = await fetchImpl(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MS), redirect: 'follow' });
      if (res.status === 304) {
        meta.status = 'ok';
        meta.error = null;
        writeAtomic(feedPath(f.id, META_FILE), JSON.stringify(meta, null, 2));
        return { feed_id: f.id, status: 'not_modified', bytes: meta.bytes, ms: Date.now() - started };
      }
      if (!res.ok) {
        lastErr = `HTTP ${res.status}`;
        continue;
      }
      const body = await readCapped(res);
      if (!body.length) {
        lastErr = 'empty body';
        continue;
      }
      const entries = countEntries(f.format, body);
      if (entries === 0) {
        lastErr = 'no entries (kept previous data)';
        continue;
      }
      writeAtomic(feedPath(f.id, DATA_FILE), body);
      Object.assign(meta, {
        status: 'ok',
        url,
        etag: res.headers.get('etag'),
        last_modified: res.headers.get('last-modified'),
        fetched_at: now.toISOString(),
        bytes: body.length,
        sha256: crypto.createHash('sha256').update(body).digest('hex'),
        entries,
        error: null,
      } satisfies Partial<MirrorMeta>);
      writeAtomic(feedPath(f.id, META_FILE), JSON.stringify(meta, null, 2));
      return { feed_id: f.id, status: 'updated', bytes: body.length, ms: Date.now() - started };
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
    }
  }
  meta.status = 'error';
  meta.error = lastErr.slice(0, 300);
  writeAtomic(feedPath(f.id, META_FILE), JSON.stringify(meta, null, 2));
  return { feed_id: f.id, status: 'error', bytes: meta.bytes, ms: Date.now() - started, detail: meta.error };
}

const g = globalThis as unknown as { __asaFeedSync?: Promise<SyncOutcome[]> | null; __asaFeedSyncAt?: number };

/**
 * 同步所有可鏡像的清單（同時間只跑一次；`force` 忽略更新間隔）。
 * 沒到期的回 `fresh`，廠商回 304 的回 `not_modified`，失敗保留舊資料。
 */
export function syncFeeds(opts: { force?: boolean; only?: string[]; fetchImpl?: FetchFn; version?: string } = {}): Promise<SyncOutcome[]> {
  if (g.__asaFeedSync) return g.__asaFeedSync;
  const run = (async () => {
    const now = Date.now();
    const nc = await allowNoncommercial(getDb());
    const targets = loadRegistry().filter((f) => mirrorable(f, nc) && (!opts.only?.length || opts.only.includes(f.id)));
    const out: SyncOutcome[] = [];
    const queue = [...targets];
    const worker = async () => {
      for (let f = queue.shift(); f; f = queue.shift()) {
        const prev = readMeta(f.id);
        if (!opts.force && isFresh(f, prev, now)) {
          out.push({ feed_id: f.id, status: 'fresh', bytes: prev?.bytes ?? 0, ms: 0 });
          continue;
        }
        out.push(await fetchOne(f, prev, opts.fetchImpl ?? fetch, opts.version ?? (readEnv('ASA_HUB_VERSION') || 'dev')));
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    g.__asaFeedSyncAt = Date.now();
    return out.sort((a, b) => a.feed_id.localeCompare(b.feed_id));
  })();
  g.__asaFeedSync = run;
  run.finally(() => {
    g.__asaFeedSync = null;
  }).catch(() => {});
  return run;
}

/** 背景補抓（agent 要清單或有人看情資頁時觸發；10 分鐘內最多檢查一次，不等結果）。 */
export function syncInBackground(): void {
  if (readEnv('ASA_HUB_FEED_MIRROR') === '0') return;
  if (g.__asaFeedSync || (g.__asaFeedSyncAt && Date.now() - g.__asaFeedSyncAt < 10 * 60_000)) return;
  g.__asaFeedSyncAt = Date.now();
  syncFeeds().catch(() => {});
}

export function syncRunning(): boolean {
  return !!g.__asaFeedSync;
}

export interface ManifestEntry {
  id: string;
  sha256: string;
  bytes: number;
  fetched_at: string | null;
  checked_at: string | null;
  url: string;
}

/** 給 agent 的清單：有資料的鏡像。 */
export function manifest(noncommercial = false): ManifestEntry[] {
  return loadRegistry()
    .filter((f) => mirrorable(f, noncommercial))
    .flatMap((f) => {
      const m = readMeta(f.id);
      if (!m?.sha256 || !dataPath(f.id)) return [];
      return [{ id: f.id, sha256: m.sha256, bytes: m.bytes, fetched_at: m.fetched_at, checked_at: m.checked_at, url: `/api/v1/feeds/${f.id}` }];
    });
}

/** 重置（測試用）。 */
export function resetMirrorStateForTests(): void {
  g.__asaFeedSync = null;
  g.__asaFeedSyncAt = undefined;
}
