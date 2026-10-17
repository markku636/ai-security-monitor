// 遠端 IP 的人工備註：一個 IP 一則，清空即刪除。
import { eq, inArray } from 'drizzle-orm';
import { ipNotes } from '@/drizzle/schema';
import { getDb } from '@/lib/db';

export const NOTE_MAX = 2000;

export type IpNote = typeof ipNotes.$inferSelect;

export async function getIpNote(ip: string): Promise<IpNote | null> {
  const [row] = await getDb().select().from(ipNotes).where(eq(ipNotes.ip, ip)).limit(1);
  return row ?? null;
}

/** 多個 IP 的備註（清單頁用）；回傳 ip → 備註文字。 */
export async function ipNoteMap(ips: (string | null | undefined)[]): Promise<Map<string, string>> {
  const list = [...new Set(ips.filter((x): x is string => !!x))];
  if (!list.length) return new Map();
  const rows = await getDb().select({ ip: ipNotes.ip, note: ipNotes.note }).from(ipNotes).where(inArray(ipNotes.ip, list));
  return new Map(rows.map((r) => [r.ip, r.note]));
}

/** 寫入或刪除（note 去頭尾空白後為空就刪）；回傳寫入後的備註，刪除回 null。 */
export async function setIpNote(ip: string, note: string, actor: string): Promise<IpNote | null> {
  const db = getDb();
  const text = note.trim();
  if (!text) {
    await db.delete(ipNotes).where(eq(ipNotes.ip, ip));
    return null;
  }
  const now = new Date();
  const [row] = await db
    .insert(ipNotes)
    .values({ ip, note: text, updatedAt: now, updatedBy: actor })
    .onConflictDoUpdate({ target: ipNotes.ip, set: { note: text, updatedAt: now, updatedBy: actor } })
    .returning();
  return row;
}
