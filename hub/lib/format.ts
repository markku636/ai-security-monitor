// 顯示用格式化（server／client 共用）。
import type { TFn } from '@/lib/i18n/core';

/** 「N 秒／分鐘／小時／天前」。 */
export function since(d: Date | string | null | undefined, t: TFn, now = Date.now()): string {
  if (!d) return '—';
  const ms = typeof d === 'string' ? Date.parse(d) : d.getTime();
  if (!Number.isFinite(ms)) return '—';
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return t('{n} 秒前', { n: s });
  if (s < 3600) return t('{n} 分鐘前', { n: Math.round(s / 60) });
  if (s < 86400) return t('{n} 小時前', { n: Math.round(s / 3600) });
  return t('{n} 天前', { n: Math.round(s / 86400) });
}

/** ISO 時間 → `YYYY-MM-DD HH:mm`（UTC；頁面上一律標 UTC，避免伺服器／瀏覽器時區不一致）。 */
export function utc(d: Date | string | null | undefined): string {
  if (!d) return '—';
  const iso = typeof d === 'string' ? d : d.toISOString();
  return `${iso.slice(0, 16).replace('T', ' ')} UTC`;
}

/** IPv6 位址加中括號再接 port。 */
export function endpoint(ip: string | null | undefined, port: number | null | undefined): string {
  if (!ip) return '—';
  const host = ip.includes(':') ? `[${ip}]` : ip;
  return port == null ? host : `${host}:${port}`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** 位元組（含 GB／TB），小數一位。 */
export function fmtBytes(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = Math.max(0, n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${Math.round(v)} B` : `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

/** 速率（bytes/s）。 */
export function fmtRate(n: number | null | undefined): string {
  return n == null ? '—' : `${fmtBytes(n)}/s`;
}

/** 百分比（整數）。 */
export function fmtPct(n: number | null | undefined): string {
  return n == null || !Number.isFinite(n) ? '—' : `${Math.round(n)}%`;
}
