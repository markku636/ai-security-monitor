// 掃描目標：新增、列表、刪除、擁有權驗證（DNS TXT 由 Hub 直接查；/.well-known 檔與 meta 交給 runner 去抓，Hub 不連目標）。
import crypto from 'node:crypto';
import net from 'node:net';
import { and, desc, eq, inArray, isNull, sql } from 'drizzle-orm';
import { webFindings, webscanJobs, webTargets } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { VERIFY_TTL_DAYS, WEBSCAN_OPEN_STATUSES } from './scanners';
import { parseTargetUrl, resolveAndScreen, resolveTxt, screenIps, type ScreenResult } from './scope';
import { getWebscanSettings } from './settings';

export const MAX_TARGETS = 500;
/** 真的證明過擁有權的方式（internal-cidr 只是「管理員把這個網段列進白名單」的紀錄，不算）。 */
const PROOF_METHODS = ['dns-txt', 'well-known', 'meta'];

export type TargetRow = typeof webTargets.$inferSelect;

function hex(bytes: number): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export const newTargetId = () => `wt_${hex(8)}`;
export const newVerifyToken = () => `asm-verify-${hex(16)}`;

/** DNS TXT 要放的名稱：`_asm-verify.<host>`（也接受直接放在 host 本身）。 */
export function verifyTxtName(host: string): string {
  return `_asm-verify.${host}`;
}

/** 擁有權證明還有效嗎（過期要重新驗證才能做主動掃描）。 */
export function proofState(t: Pick<TargetRow, 'verifyMethod' | 'verifiedAt'>, now = new Date()) {
  const proven = !!t.verifiedAt && PROOF_METHODS.includes(t.verifyMethod ?? '');
  const expiresAt = proven ? new Date(t.verifiedAt!.getTime() + VERIFY_TTL_DAYS * 86_400_000) : null;
  return { proven: proven && !!expiresAt && expiresAt.getTime() > now.getTime(), expired: proven && !!expiresAt && expiresAt.getTime() <= now.getTime(), expiresAt };
}

export async function getTarget(db: DB, id: string): Promise<TargetRow | null> {
  return (await db.select().from(webTargets).where(and(eq(webTargets.id, id), isNull(webTargets.deletedAt))).limit(1))[0] ?? null;
}

export async function createTarget(
  db: DB,
  input: { url: string; name?: string },
  actor: string,
): Promise<{ target: TargetRow; screen: ScreenResult } | { error: string }> {
  const p = parseTargetUrl(input.url);
  if ('error' in p) return { error: p.error };
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(webTargets).where(isNull(webTargets.deletedAt));
  if (Number(n) >= MAX_TARGETS) return { error: 'too_many_targets' };
  const dup = await db.select({ id: webTargets.id }).from(webTargets).where(and(eq(webTargets.url, p.url), isNull(webTargets.deletedAt))).limit(1);
  if (dup.length) return { error: 'duplicate' };
  const screen = await resolveAndScreen(p.host, { internalCidrs: (await getWebscanSettings(db)).internal_cidrs });
  const internal = screen.ok && screen.internal;
  try {
    const [target] = await db
      .insert(webTargets)
      .values({
        id: newTargetId(),
        url: p.url,
        scheme: p.scheme,
        host: p.host,
        port: p.port,
        path: p.path,
        name: (input.name ?? '').trim().slice(0, 120),
        verifyToken: newVerifyToken(),
        // 內網白名單裡的位址：管理員已經聲明這是自己的網段（只做紀錄；每次建立工作仍重新解析檢查）
        verifyMethod: internal ? 'internal-cidr' : null,
        verifiedAt: internal ? new Date() : null,
        createdBy: actor,
      })
      .returning();
    return { target, screen };
  } catch {
    return { error: 'duplicate' };
  }
}

export async function deleteTarget(db: DB, id: string): Promise<boolean> {
  const t = await getTarget(db, id);
  if (!t) return false;
  const now = new Date();
  await db.update(webTargets).set({ deletedAt: now }).where(eq(webTargets.id, id));
  await db
    .update(webscanJobs)
    .set({ status: 'cancelled', finishedAt: now, error: 'target_deleted' })
    .where(and(eq(webscanJobs.targetId, id), inArray(webscanJobs.status, WEBSCAN_OPEN_STATUSES)));
  return true;
}

/** DNS TXT 驗證（Hub 只查 DNS）：`_asm-verify.<host>` 或 host 本身的 TXT 含驗證碼就通過。 */
export async function verifyByDnsTxt(db: DB, t: TargetRow, now = new Date()): Promise<{ verified: boolean; error: string | null }> {
  if (net.isIP(t.host)) return finishVerify(db, t, 'dns-txt', false, 'ip_has_no_dns', now);
  const records = [...(await resolveTxt(verifyTxtName(t.host))), ...(await resolveTxt(t.host))];
  const found = records.some((r) => r.trim().includes(t.verifyToken));
  return finishVerify(db, t, 'dns-txt', found, found ? null : 'txt_not_found', now);
}

/**
 * 「內網白名單」標記跟著最新的位址走：位址在白名單內就標 internal-cidr（已有真正的擁有權證明時不動），
 * 不在了（白名單拿掉、DNS 改指到公網）就清掉，畫面上的狀態與主動掃描按鈕才不會跟伺服器的判斷不一致。
 */
export async function syncInternalMark(db: DB, t: TargetRow, internal: boolean, now = new Date()): Promise<void> {
  if (internal && t.verifyMethod !== 'internal-cidr' && !proofState(t, now).proven) {
    await db.update(webTargets).set({ verifyMethod: 'internal-cidr', verifiedAt: now }).where(eq(webTargets.id, t.id));
  } else if (!internal && t.verifyMethod === 'internal-cidr') {
    await db.update(webTargets).set({ verifyMethod: null, verifiedAt: null }).where(eq(webTargets.id, t.id));
  }
}

/** 設定頁改了內網白名單：直接用 IP 的目標不用查 DNS，馬上重新標記（用網域的在下一次建立工作時更新）。 */
export async function remarkIpTargets(db: DB, internalCidrs: string[]): Promise<void> {
  const rows = await db.select().from(webTargets).where(isNull(webTargets.deletedAt));
  for (const t of rows.filter((r) => net.isIP(r.host))) {
    const s = screenIps([t.host], { internalCidrs });
    await syncInternalMark(db, t, s.ok && s.internal);
  }
}

/** 記下驗證結果；通過才更新方法與時間（失敗不會把之前有效的證明清掉）。 */
export async function finishVerify(db: DB, t: TargetRow, method: string, found: boolean, err: string | null, now = new Date()) {
  await db
    .update(webTargets)
    .set(found ? { verifyMethod: method, verifiedAt: now, verifyCheckedAt: now, verifyError: null } : { verifyCheckedAt: now, verifyError: (err ?? 'not_found').slice(0, 200) })
    .where(eq(webTargets.id, t.id));
  return { verified: found, error: found ? null : err };
}

/** 目標清單＋每個目標未處理問題的嚴重度計數。 */
export async function listTargets(db: DB) {
  const rows = await db.select().from(webTargets).where(isNull(webTargets.deletedAt)).orderBy(desc(webTargets.createdAt)).limit(MAX_TARGETS);
  const counts = await db
    .select({ targetId: webFindings.targetId, severity: webFindings.severity, n: sql<number>`count(*)::int` })
    .from(webFindings)
    .where(eq(webFindings.status, 'open'))
    .groupBy(webFindings.targetId, webFindings.severity);
  const by = new Map<string, Record<string, number>>();
  for (const c of counts) {
    const m = by.get(c.targetId) ?? {};
    m[c.severity] = Number(c.n);
    by.set(c.targetId, m);
  }
  const now = new Date();
  return rows.map((r) => {
    const sev = by.get(r.id) ?? {};
    const proof = proofState(r, now);
    return {
      ...publicTarget(r),
      proven: proof.proven,
      proofExpired: proof.expired,
      counts: { critical: sev.critical ?? 0, high: sev.high ?? 0, medium: sev.medium ?? 0, low: sev.low ?? 0, info: sev.info ?? 0 },
    };
  });
}

export function publicTarget(r: TargetRow) {
  return {
    id: r.id,
    url: r.url,
    scheme: r.scheme,
    host: r.host,
    port: r.port,
    path: r.path,
    name: r.name,
    verifyToken: r.verifyToken,
    verifyMethod: r.verifyMethod,
    verifiedAt: r.verifiedAt?.toISOString() ?? null,
    verifyCheckedAt: r.verifyCheckedAt?.toISOString() ?? null,
    verifyError: r.verifyError,
    fingerprint: r.fingerprint,
    lastScanAt: r.lastScanAt?.toISOString() ?? null,
    lastJobId: r.lastJobId,
    createdAt: r.createdAt.toISOString(),
    createdBy: r.createdBy,
  };
}
export type TargetListItem = Awaited<ReturnType<typeof listTargets>>[number];
