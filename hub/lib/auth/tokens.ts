// API token 與註冊金鑰：產生時只回傳一次明文，資料庫只存 sha256；以 8 碼 id 定位後常數時間比對。
//   API token  asa_<8hex>_<40hex>     唯讀，scope：read（API）、export（CSV）、mcp（Hub MCP）
//   註冊金鑰    asa_ek_<8hex>_<40hex>  agent 上傳用（等同 ASA_HUB_CLIENT_SECRETS 裡的一把，但可在網頁建立／撤銷）
import crypto from 'node:crypto';
import { and, desc, eq, isNull, sql } from 'drizzle-orm';
import { apiTokens, enrollKeys } from '@/drizzle/schema';
import { getDb } from '@/lib/db';
import { safeEqual, sha256Hex } from './crypto';

export const TOKEN_SCOPES = ['read', 'export', 'mcp'] as const;
export type TokenScope = (typeof TOKEN_SCOPES)[number];

const API_RE = /^asa_([0-9a-f]{8})_([0-9a-f]{40})$/;
const ENROLL_RE = /^asa_ek_([0-9a-f]{8})_([0-9a-f]{40})$/;

function hex(bytes: number): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export function isApiTokenShape(t: string): boolean {
  return API_RE.test(t);
}

export function isEnrollKeyShape(t: string): boolean {
  return ENROLL_RE.test(t);
}

/** 最後使用時間最多每分鐘寫一次，避免每個請求都寫 DB。 */
const touched = new Map<string, number>();
function shouldTouch(id: string): boolean {
  const now = Date.now();
  const last = touched.get(id) ?? 0;
  if (now - last < 60_000) return false;
  touched.set(id, now);
  return true;
}

export async function createApiToken(o: { name: string; scopes: TokenScope[]; expiresDays?: number | null; actor: string }) {
  const id = hex(4);
  const token = `asa_${id}_${hex(20)}`;
  const expiresAt = o.expiresDays ? new Date(Date.now() + o.expiresDays * 86_400_000) : null;
  const [row] = await getDb()
    .insert(apiTokens)
    .values({ id, name: o.name, tokenHash: sha256Hex(token), scopes: [...new Set(o.scopes)], createdBy: o.actor, expiresAt })
    .returning();
  return { token, row: publicToken(row) };
}

export async function createEnrollKey(o: { name: string; actor: string }) {
  const id = hex(4);
  const key = `asa_ek_${id}_${hex(20)}`;
  const [row] = await getDb().insert(enrollKeys).values({ id, name: o.name, keyHash: sha256Hex(key), createdBy: o.actor }).returning();
  return { key, row: publicEnrollKey({ ...row, agents: 0 }) };
}

/** 有效的 API token → { id, scopes }。 */
export async function verifyApiToken(token: string): Promise<{ id: string; scopes: TokenScope[] } | null> {
  const m = API_RE.exec(token);
  if (!m) return null;
  const [row] = await getDb().select().from(apiTokens).where(eq(apiTokens.id, m[1])).limit(1);
  if (!row || row.revokedAt || (row.expiresAt && row.expiresAt.getTime() < Date.now())) return null;
  if (!safeEqual(sha256Hex(token), row.tokenHash)) return null;
  if (shouldTouch(`t:${row.id}`)) {
    await getDb().update(apiTokens).set({ lastUsedAt: new Date() }).where(eq(apiTokens.id, row.id));
  }
  return { id: row.id, scopes: (row.scopes ?? []).filter((s): s is TokenScope => (TOKEN_SCOPES as readonly string[]).includes(s)) };
}

export async function verifyEnrollKey(key: string): Promise<{ id: string } | null> {
  const m = ENROLL_RE.exec(key);
  if (!m) return null;
  const [row] = await getDb().select().from(enrollKeys).where(eq(enrollKeys.id, m[1])).limit(1);
  if (!row || row.revokedAt) return null;
  if (!safeEqual(sha256Hex(key), row.keyHash)) return null;
  if (shouldTouch(`e:${row.id}`)) {
    await getDb().update(enrollKeys).set({ lastUsedAt: new Date() }).where(eq(enrollKeys.id, row.id));
  }
  return { id: row.id };
}

type TokenRow = typeof apiTokens.$inferSelect;
type EnrollRow = typeof enrollKeys.$inferSelect & { agents: number };

function publicToken(r: TokenRow) {
  const expired = !!r.expiresAt && r.expiresAt.getTime() < Date.now();
  return {
    id: r.id,
    name: r.name,
    hint: `asa_${r.id}_…`,
    scopes: r.scopes,
    createdAt: r.createdAt,
    createdBy: r.createdBy,
    expiresAt: r.expiresAt,
    lastUsedAt: r.lastUsedAt,
    revokedAt: r.revokedAt,
    status: r.revokedAt ? 'revoked' : expired ? 'expired' : 'active',
  } as const;
}

function publicEnrollKey(r: EnrollRow) {
  return {
    id: r.id,
    name: r.name,
    hint: `asa_ek_${r.id}_…`,
    createdAt: r.createdAt,
    createdBy: r.createdBy,
    lastUsedAt: r.lastUsedAt,
    revokedAt: r.revokedAt,
    agents: r.agents,
    status: r.revokedAt ? 'revoked' : 'active',
  } as const;
}

export type ApiTokenView = ReturnType<typeof publicToken>;
export type EnrollKeyView = ReturnType<typeof publicEnrollKey>;

export async function listApiTokens(): Promise<ApiTokenView[]> {
  return (await getDb().select().from(apiTokens).orderBy(desc(apiTokens.createdAt)).limit(500)).map(publicToken);
}

export async function listEnrollKeys(): Promise<EnrollKeyView[]> {
  const rows = await getDb()
    .select({
      key: enrollKeys,
      // 子查詢要寫明資料表：單表 select 時 drizzle 會省略欄位的表名前綴
      agents: sql<number>`(select count(*)::int from agents a where a.enroll_key_id = enroll_keys.id and a.deleted_at is null)`,
    })
    .from(enrollKeys)
    .orderBy(desc(enrollKeys.createdAt))
    .limit(500);
  return rows.map((r) => publicEnrollKey({ ...r.key, agents: Number(r.agents) }));
}

export async function revokeApiToken(id: string): Promise<boolean> {
  const r = await getDb()
    .update(apiTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(apiTokens.id, id), isNull(apiTokens.revokedAt)))
    .returning({ id: apiTokens.id });
  return r.length > 0;
}

export async function revokeEnrollKey(id: string): Promise<boolean> {
  const r = await getDb()
    .update(enrollKeys)
    .set({ revokedAt: new Date() })
    .where(and(eq(enrollKeys.id, id), isNull(enrollKeys.revokedAt)))
    .returning({ id: enrollKeys.id });
  return r.length > 0;
}

export function resetTokenTouchForTests() {
  touched.clear();
}
