// 環境變數：每個 *_SECRET / *_KEY 也接受 <名稱>_FILE（Docker secrets）。
import fs from 'node:fs';

export type Edition = 'server' | 'standalone';

export interface HubEnv {
  adminSecret: string;
  clientSecrets: string[];
  databaseUrl: string;
  publicDashboard: boolean;
  trustProxy: boolean;
  edition: Edition;
  version: string;
  /** 同一 agent 兩次完整報告的最短間隔。 */
  reportMinIntervalMs: number;
  /** 連線快照 / 心跳的最短間隔。 */
  snapshotMinIntervalMs: number;
  /** 超過這段時間沒消息就算「離線」（之內但超過快照間隔兩倍算「延遲」）。 */
  staleAfterMs: number;
  /** 流量／效能原始樣本（每分鐘）保留天數。 */
  metricsRawDays: number;
  /** 流量／效能每小時彙總保留天數。 */
  metricsHourlyDays: number;
  /** DNS 查詢紀錄原始資料保留天數（預設 7）。 */
  dnsRawDays: number;
  /** DNS 每小時彙總保留天數（預設 90）。 */
  dnsHourlyDays: number;
  /** AI 分析紀錄保留天數（0＝不自動清）。 */
  aiRetentionDays: number;
  /** 外部情資查詢快取保留天數（0＝不自動清）。 */
  ipIntelCacheDays: number;
  /** compose 內建防護 DNS 用的權杖（`AI_SECURITY_MONITOR_HUB_DNS_TOKEN`，至少 32 字元；沒設＝只能用網頁建立的 dns 權杖）。 */
  dnsServerToken: string;
}

/** 改名後的新前綴：ASA_X 也接受 AI_SECURITY_MONITOR_X，新名優先（舊名繼續有效）。 */
export const NEW_ENV_PREFIX = 'AI_SECURITY_MONITOR_';

/** 同一個設定的候選變數名（新名在前）。 */
export function envAliases(name: string): string[] {
  return name.startsWith('ASA_') ? [NEW_ENV_PREFIX + name.slice(4), name] : [name];
}

function raw(name: string): string {
  for (const n of envAliases(name)) {
    const file = process.env[`${n}_FILE`];
    if (file) {
      try {
        return fs.readFileSync(file, 'utf8').trim();
      } catch {
        return '';
      }
    }
    const v = (process.env[n] ?? '').trim();
    if (v) return v;
  }
  return '';
}

/** 給其他模組讀選用設定（同樣支援 _FILE）。 */
export function readEnv(name: string): string {
  return raw(name);
}

/** Google login is shown only when credentials and an explicit email allowlist are all set. */
export function googleLoginEnabled(): boolean {
  return !!raw('ASA_HUB_GOOGLE_CLIENT_ID') && !!raw('ASA_HUB_GOOGLE_CLIENT_SECRET') && !!raw('ASA_HUB_GOOGLE_ALLOWED_EMAILS');
}

function flag(name: string): boolean {
  return ['1', 'true', 'yes', 'on'].includes(raw(name).toLowerCase());
}

function num(name: string, dflt: number): number {
  const v = raw(name);
  if (v === '') return dflt;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : dflt;
}

export class EnvError extends Error {}

export function loadEnv(): HubEnv {
  const adminSecret = raw('ASA_HUB_ADMIN_SECRET');
  const clientSecrets = raw('ASA_HUB_CLIENT_SECRETS')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (clientSecrets.length && !adminSecret) {
    throw new EnvError('AI_SECURITY_MONITOR_HUB_CLIENT_SECRETS needs AI_SECURITY_MONITOR_HUB_ADMIN_SECRET to be set as well (legacy ASA_HUB_* names also work)');
  }
  if (adminSecret && clientSecrets.includes(adminSecret)) {
    throw new EnvError('AI_SECURITY_MONITOR_HUB_ADMIN_SECRET and AI_SECURITY_MONITOR_HUB_CLIENT_SECRETS must all be different');
  }
  if (new Set(clientSecrets).size !== clientSecrets.length) {
    throw new EnvError('AI_SECURITY_MONITOR_HUB_CLIENT_SECRETS contains duplicates');
  }
  return {
    adminSecret,
    clientSecrets,
    databaseUrl: raw('ASA_HUB_DATABASE_URL'),
    publicDashboard: flag('ASA_HUB_PUBLIC_DASHBOARD'),
    trustProxy: flag('ASA_HUB_TRUST_PROXY'),
    edition: raw('ASA_HUB_EDITION') === 'server' ? 'server' : 'standalone',
    version: raw('ASA_HUB_VERSION') || process.env.npm_package_version || '0.8.1',
    reportMinIntervalMs: num('ASA_HUB_INGEST_MIN_INTERVAL_MS', 60_000),
    snapshotMinIntervalMs: num('ASA_HUB_SNAPSHOT_MIN_INTERVAL_MS', 10_000),
    staleAfterMs: num('ASA_HUB_STALE_AFTER_MS', 30 * 60_000),
    metricsRawDays: Math.min(90, Math.max(1, num('ASA_HUB_METRICS_RAW_DAYS', 7))),
    metricsHourlyDays: Math.min(3650, Math.max(1, num('ASA_HUB_METRICS_HOURLY_DAYS', 90))),
    dnsRawDays: Math.min(90, Math.max(1, num('ASA_HUB_DNS_RAW_DAYS', 7))),
    dnsHourlyDays: Math.min(3650, Math.max(1, num('ASA_HUB_DNS_HOURLY_DAYS', 90))),
    aiRetentionDays: Math.min(3650, num('ASA_HUB_AI_RETENTION_DAYS', 90)),
    ipIntelCacheDays: Math.min(3650, num('ASA_HUB_IPINTEL_CACHE_DAYS', 30)),
    dnsServerToken: raw('ASA_HUB_DNS_TOKEN').length >= 32 ? raw('ASA_HUB_DNS_TOKEN') : '',
  };
}

const g = globalThis as unknown as { __asaEnv?: HubEnv };

export function env(): HubEnv {
  if (!g.__asaEnv) g.__asaEnv = loadEnv();
  return g.__asaEnv;
}

export function resetEnvForTests(): void {
  g.__asaEnv = undefined;
}

/** 沒有管理員金鑰＝開放模式（只該綁 loopback）。 */
export function isOpenMode(): boolean {
  return !env().adminSecret && !googleLoginEnabled();
}
