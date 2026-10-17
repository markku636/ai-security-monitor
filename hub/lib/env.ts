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
}

function raw(name: string): string {
  const file = process.env[`${name}_FILE`];
  if (file) {
    try {
      return fs.readFileSync(file, 'utf8').trim();
    } catch {
      return '';
    }
  }
  return (process.env[name] ?? '').trim();
}

/** 給其他模組讀選用設定（同樣支援 _FILE）。 */
export function readEnv(name: string): string {
  return raw(name);
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
    throw new EnvError('ASA_HUB_CLIENT_SECRETS needs ASA_HUB_ADMIN_SECRET to be set as well');
  }
  if (adminSecret && clientSecrets.includes(adminSecret)) {
    throw new EnvError('ASA_HUB_ADMIN_SECRET and ASA_HUB_CLIENT_SECRETS must all be different');
  }
  if (new Set(clientSecrets).size !== clientSecrets.length) {
    throw new EnvError('ASA_HUB_CLIENT_SECRETS contains duplicates');
  }
  return {
    adminSecret,
    clientSecrets,
    databaseUrl: raw('ASA_HUB_DATABASE_URL'),
    publicDashboard: flag('ASA_HUB_PUBLIC_DASHBOARD'),
    trustProxy: flag('ASA_HUB_TRUST_PROXY'),
    edition: raw('ASA_HUB_EDITION') === 'server' ? 'server' : 'standalone',
    version: raw('ASA_HUB_VERSION') || process.env.npm_package_version || '0.1.0',
    reportMinIntervalMs: num('ASA_HUB_INGEST_MIN_INTERVAL_MS', 60_000),
    snapshotMinIntervalMs: num('ASA_HUB_SNAPSHOT_MIN_INTERVAL_MS', 10_000),
    staleAfterMs: num('ASA_HUB_STALE_AFTER_MS', 30 * 60_000),
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
  return !env().adminSecret;
}
