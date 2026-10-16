// 管理頁：稽核紀錄、CSV 匯出用的查詢。
import { desc, ilike } from 'drizzle-orm';
import { auditLog } from '@/drizzle/schema';
import { getDb } from '@/lib/db';

export async function listAudit(o: { limit?: number; action?: string } = {}) {
  const q = getDb().select().from(auditLog);
  const rows = await (o.action ? q.where(ilike(auditLog.action, `${o.action.replace(/[%_]/g, '')}%`)) : q)
    .orderBy(desc(auditLog.at))
    .limit(Math.min(o.limit ?? 100, 1000));
  return rows;
}

/** CSV：欄位含逗號、引號、換行就加引號；開頭是 = + - @ 的加 ' 防試算表公式注入。 */
export function csvCell(v: unknown): string {
  if (v === null || v === undefined) return '';
  let s = v instanceof Date ? v.toISOString() : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(header: string[], rows: unknown[][]): string {
  // BOM：Excel 才會用 UTF-8 開中文
  return '﻿' + [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
