// 免金鑰加入申請：建立（冪等）、輪詢、核准／拒絕、加入模式（自動允許／審核）與自動核准網段、到期。
// 安全重點：request_secret 只存 sha256、比對用 safeEqual；核准前絕不回任何憑證；
// 核准後發的註冊金鑰不存明文（以 enroll_credential_secret HMAC 衍生），而且只綁那台 agent（bound_agent_id）。
import crypto from 'node:crypto';
import { and, desc, eq, gte, inArray, isNull, lt, sql } from 'drizzle-orm';
import { z } from 'zod';
import { agents, enrollKeys, enrollmentRequests, settings } from '@/drizzle/schema';
import { audit } from '@/lib/audit';
import { safeEqual, sha256Hex } from '@/lib/auth/crypto';
import type { DB } from '@/lib/db';
import { readEnv } from '@/lib/env';
import { AgentInfo } from '@/lib/ingest/schema';
import { matchCidr, normalizeCidrList, type CidrError } from './cidr';
import { approvalMessage, hubIdentity, requestCodeOf, sign } from './identity';

export const REQUEST_TTL_MS = 7 * 86_400_000;
export const CLAIM_WINDOW_MS = 10 * 60_000;
export const POLL_INTERVAL_S = 15;
/** 同一來源 IP 每 10 分鐘最多送幾次申請（整間辦公室在同一個 NAT／代理後面一起安裝也夠用；待核准總數另有上限）。 */
export const CREATE_WINDOW_MS = 10 * 60_000;
export const CREATES_PER_WINDOW = 120;
export const STATUSES = ['pending', 'approved', 'rejected', 'expired'] as const;
export type EnrollStatus = (typeof STATUSES)[number];

const CIDR_KEY = 'enroll_auto_approve_cidrs';
const MODE_KEY = 'enroll_join_mode';
/** 加入模式：auto＝申請一送出就自動核准（預設）；review＝要管理員核准（自動核准網段內的仍自動）。 */
export const JOIN_MODES = ['auto', 'review'] as const;
export type JoinMode = (typeof JOIN_MODES)[number];
export const DEFAULT_JOIN_MODE: JoinMode = 'auto';
/** 自動核准的煞車：全 Hub 每 10 分鐘最多 60 筆、已核准但還沒領走的最多 500 筆；超過改成等人工核准。 */
export const AUTO_WINDOW_MS = 10 * 60_000;
export const AUTO_PER_WINDOW = 60;
export const AUTO_UNCLAIMED_CAP = 500;
const CRED_KEY = 'enroll_credential_secret';

export const SECRET_RE = /^[A-Za-z0-9_-]{43,128}$/;
export const REQUEST_ID_RE = /^rq_[0-9a-f]{24}$/;

export const EnrollRequest = z
  .object({
    agent: AgentInfo,
    accept_remote_actions: z.boolean().default(false),
    request_secret: z.string().regex(SECRET_RE),
    hub_fingerprint: z.string().max(64).nullish(),
  })
  .passthrough();
export type EnrollRequestT = z.infer<typeof EnrollRequest>;

export type EnrollRow = typeof enrollmentRequests.$inferSelect;

const g = globalThis as unknown as { __asaEnrollPendingCap?: number; __asaEnrollCredSecret?: string };

export function pendingCap(): number {
  return g.__asaEnrollPendingCap ?? 500;
}

/** 測試用：調低待核准上限（不給參數＝還原 500）。 */
export function setPendingCapForTests(n?: number): void {
  g.__asaEnrollPendingCap = n;
}

export function resetEnrollSecretsForTests(): void {
  g.__asaEnrollCredSecret = undefined;
}

/** 衍生註冊金鑰用的秘密（第一次用到時隨機產生並存進 settings）。 */
async function credentialSecret(db: DB): Promise<string> {
  if (g.__asaEnrollCredSecret) return g.__asaEnrollCredSecret;
  const read = async () => (await db.select().from(settings).where(eq(settings.key, CRED_KEY)).limit(1))[0];
  let row = await read();
  if (typeof row?.value !== 'string' || !row.value) {
    await db.insert(settings).values({ key: CRED_KEY, value: crypto.randomBytes(32).toString('hex'), updatedBy: 'system' }).onConflictDoNothing();
    row = await read();
  }
  const v = String(row?.value ?? '');
  if (!v) throw new Error('enroll_credential_secret unavailable');
  g.__asaEnrollCredSecret = v;
  return v;
}

export function deriveClientKey(secret: string, requestId: string, keyId: string): string {
  const tail = crypto.createHmac('sha256', secret).update(`asa-enroll-key|${requestId}|${keyId}`).digest('hex').slice(0, 40);
  return `asa_ek_${keyId}_${tail}`;
}

// ---- 加入模式 ----

function isJoinMode(v: unknown): v is JoinMode {
  return typeof v === 'string' && (JOIN_MODES as readonly string[]).includes(v);
}

/** 環境變數 ASA_HUB_ENROLL_MODE（或 AI_SECURITY_MONITOR_HUB_ENROLL_MODE）＞ 網頁設定 ＞ 預設 auto。 */
export async function getJoinMode(db: DB): Promise<{ mode: JoinMode; source: 'env' | 'settings' | 'default' }> {
  const fromEnv = readEnv('ASA_HUB_ENROLL_MODE').trim().toLowerCase();
  if (isJoinMode(fromEnv)) return { mode: fromEnv, source: 'env' };
  const row = (await db.select().from(settings).where(eq(settings.key, MODE_KEY)).limit(1))[0];
  if (isJoinMode(row?.value)) return { mode: row.value, source: 'settings' };
  return { mode: DEFAULT_JOIN_MODE, source: 'default' };
}

export async function setJoinMode(db: DB, input: unknown, actor: string): Promise<{ before: JoinMode; after: JoinMode } | { error: 'bad_mode' | 'locked_by_env' }> {
  if (!isJoinMode(input)) return { error: 'bad_mode' };
  const cur = await getJoinMode(db);
  if (cur.source === 'env') return { error: 'locked_by_env' };
  await db
    .insert(settings)
    .values({ key: MODE_KEY, value: input, updatedBy: actor, updatedAt: new Date() })
    .onConflictDoUpdate({ target: settings.key, set: { value: input, updatedBy: actor, updatedAt: new Date() } });
  return { before: cur.mode, after: input };
}

/** 自動核准的煞車有沒有踩到（回傳原因，沒踩到回 null）。 */
async function autoCapHit(db: DB, now = new Date()): Promise<'rate' | 'unclaimed' | null> {
  const [{ recent }] = await db
    .select({ recent: sql<number>`count(*)::int` })
    .from(enrollmentRequests)
    .where(and(eq(enrollmentRequests.autoApproved, true), gte(enrollmentRequests.decidedAt, new Date(now.getTime() - AUTO_WINDOW_MS))));
  if (Number(recent) >= AUTO_PER_WINDOW) return 'rate';
  const [{ unclaimed }] = await db
    .select({ unclaimed: sql<number>`count(*)::int` })
    .from(enrollmentRequests)
    .where(and(eq(enrollmentRequests.status, 'approved'), isNull(enrollmentRequests.claimedAt)));
  if (Number(unclaimed) >= AUTO_UNCLAIMED_CAP) return 'unclaimed';
  return null;
}

// ---- 自動核准網段 ----

export async function getAutoApproveCidrs(db: DB): Promise<string[]> {
  const row = (await db.select().from(settings).where(eq(settings.key, CIDR_KEY)).limit(1))[0];
  const v = row?.value;
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

export async function setAutoApproveCidrs(db: DB, input: unknown, actor: string): Promise<{ before: string[]; after: string[] } | CidrError> {
  const after = normalizeCidrList(input);
  if (!Array.isArray(after)) return after;
  const before = await getAutoApproveCidrs(db);
  await db
    .insert(settings)
    .values({ key: CIDR_KEY, value: after, updatedBy: actor, updatedAt: new Date() })
    .onConflictDoUpdate({ target: settings.key, set: { value: after, updatedBy: actor, updatedAt: new Date() } });
  return { before, after };
}

// ---- 到期 ----

/** 懶惰到期：pending 超過 7 天、核准後 7 天還沒領走 → expired（順便撤銷那把沒人用的金鑰）。 */
export async function expireStale(db: DB, now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - REQUEST_TTL_MS);
  const a = await db
    .update(enrollmentRequests)
    .set({ status: 'expired' })
    .where(and(eq(enrollmentRequests.status, 'pending'), lt(enrollmentRequests.createdAt, cutoff)))
    .returning({ id: enrollmentRequests.id });
  const b = await db
    .update(enrollmentRequests)
    .set({ status: 'expired' })
    .where(and(eq(enrollmentRequests.status, 'approved'), isNull(enrollmentRequests.claimedAt), lt(enrollmentRequests.decidedAt, cutoff)))
    .returning({ id: enrollmentRequests.id, keyId: enrollmentRequests.enrollKeyId });
  const keys = b.map((r) => r.keyId).filter((k): k is string => !!k);
  if (keys.length) {
    await db.update(enrollKeys).set({ revokedAt: now }).where(and(inArray(enrollKeys.id, keys), isNull(enrollKeys.revokedAt)));
  }
  return a.length + b.length;
}

// ---- 建立 ----

export type CreateResult =
  | { ok: true; row: EnrollRow; created: boolean }
  | { ok: false; status: number; error: string; extra?: Record<string, unknown> };

export async function createRequest(
  db: DB,
  body: EnrollRequestT,
  meta: { sourceIp: string; peerIp: string | null },
): Promise<CreateResult> {
  await expireStale(db);
  const secretHash = sha256Hex(body.request_secret);
  const existing = (
    await db
      .select()
      .from(enrollmentRequests)
      .where(and(eq(enrollmentRequests.agentId, body.agent.id), inArray(enrollmentRequests.status, ['pending', 'approved'])))
      .orderBy(desc(enrollmentRequests.createdAt))
      .limit(50)
  ).find((r) => safeEqual(secretHash, r.secretHash));
  if (existing) {
    const row = existing.status === 'pending' ? ((await maybeAutoApprove(db, existing, meta)) ?? existing) : existing;
    return { ok: true, row, created: false };
  }
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(enrollmentRequests).where(eq(enrollmentRequests.status, 'pending'));
  if (Number(n) >= pendingCap()) return { ok: false, status: 503, error: 'too_many_pending' };
  const a = body.agent;
  const now = new Date();
  const [row] = await db
    .insert(enrollmentRequests)
    .values({
      id: `rq_${crypto.randomBytes(12).toString('hex')}`,
      agentId: a.id,
      hostname: a.hostname,
      osFamily: a.os.family,
      osName: a.os.name ?? null,
      osVersion: a.os.version ?? a.os.build ?? null,
      arch: a.arch,
      agentVersion: a.version,
      ips: a.ips,
      agent: a as Record<string, unknown>,
      acceptRemoteActions: body.accept_remote_actions,
      secretHash,
      requestCode: requestCodeOf(body.request_secret),
      sourceIp: meta.sourceIp,
      status: 'pending',
      createdAt: now,
      expiresAt: new Date(now.getTime() + REQUEST_TTL_MS),
    })
    .returning();
  await audit({
    actor: `enroll:${row.id}`,
    actorRole: 'none',
    action: 'enroll_request.created',
    targetType: 'enrollment_request',
    targetId: row.id,
    sourceIp: meta.sourceIp,
    details: { agent_id: a.id, hostname: a.hostname, request_code: row.requestCode },
  });
  return { ok: true, row: (await maybeAutoApprove(db, row, meta)) ?? row, created: true };
}

/**
 * 自動核准：
 * - 來源（TCP 對端，不是 X-Forwarded-For）在自動核准網段內 → 兩種模式都直接核准（decided_by＝auto:<網段>）。
 * - 自動允許模式且網段清單是空的 → 任何人都直接核准（auto:all，不需要知道來源 IP）；
 *   網段清單有填 → 只有網段內的自動，其他等管理員（「只讓公司網段自動加入」）。
 * 已登記但還沒釘選身分的舊主機一律不自動核准：那種情況光靠 agent token 擋不住冒名，要人看過。
 * 自動核准有煞車（每 10 分 60 筆、未領取 500 筆），踩到就改成等人工核准並記稽核。
 */
async function maybeAutoApprove(db: DB, row: EnrollRow, meta: { sourceIp: string; peerIp: string | null }): Promise<EnrollRow | null> {
  const { mode } = await getJoinMode(db);
  const cidrs = await getAutoApproveCidrs(db);
  const cidr = meta.peerIp ? matchCidr(meta.peerIp, cidrs) : null;
  const actor = cidr ? `auto:${cidr}` : mode === 'auto' && cidrs.length === 0 ? 'auto:all' : null;
  if (!actor) return null;
  const known = (await db.select({ tokenHash: agents.tokenHash, deletedAt: agents.deletedAt }).from(agents).where(eq(agents.id, row.agentId)).limit(1))[0];
  if (known && (!known.tokenHash || known.deletedAt)) return null;
  const cap = await autoCapHit(db);
  if (cap) {
    await audit({
      actor,
      actorRole: 'system',
      action: 'enroll_request.auto_capped',
      targetType: 'enrollment_request',
      targetId: row.id,
      sourceIp: meta.sourceIp,
      details: { agent_id: row.agentId, hostname: row.hostname, reason: cap, mode },
    });
    return null;
  }
  const done = await approveRow(db, row.id, actor, { auto: true });
  if (!done) return null;
  await audit({
    actor,
    actorRole: 'system',
    action: 'enroll_request.auto_approved',
    targetType: 'enrollment_request',
    targetId: row.id,
    sourceIp: meta.sourceIp,
    details: { agent_id: row.agentId, hostname: row.hostname, cidr, mode, peer_ip: meta.peerIp, request_code: row.requestCode },
  });
  return done;
}

/** pending → approved：同一個 transaction 建好綁定這台 agent 的註冊金鑰。不是 pending → null。 */
async function approveRow(db: DB, id: string, actor: string, opts: { auto?: boolean; reason?: string | null } = {}): Promise<EnrollRow | null> {
  const secret = await credentialSecret(db);
  return db.transaction(async (tx) => {
    const keyId = crypto.randomBytes(4).toString('hex');
    const now = new Date();
    const [row] = await tx
      .update(enrollmentRequests)
      .set({
        status: 'approved',
        decidedAt: now,
        decidedBy: actor,
        autoApproved: !!opts.auto,
        reason: opts.reason ?? null,
        enrollKeyId: keyId,
        expiresAt: new Date(now.getTime() + REQUEST_TTL_MS),
      })
      .where(and(eq(enrollmentRequests.id, id), eq(enrollmentRequests.status, 'pending')))
      .returning();
    if (!row) return null;
    const key = deriveClientKey(secret, row.id, keyId);
    await tx.insert(enrollKeys).values({
      id: keyId,
      name: `${row.hostname.slice(0, 60)} (enrollment request)`,
      keyHash: sha256Hex(key),
      createdBy: actor,
      boundAgentId: row.agentId,
    });
    return row;
  });
}

// ---- 輪詢 ----

const DUMMY_HASH = sha256Hex('asa-enroll-no-such-request');

/** 找申請＋驗 secret；不存在或 secret 錯都回 null（呼叫端一律 404，分不出來）。 */
export async function findForPoll(db: DB, id: string, secret: string | undefined): Promise<EnrollRow | null> {
  const okShape = REQUEST_ID_RE.test(id) && !!secret && SECRET_RE.test(secret);
  const row = okShape ? (await db.select().from(enrollmentRequests).where(eq(enrollmentRequests.id, id)).limit(1))[0] : undefined;
  const match = safeEqual(sha256Hex(secret ?? ''), row?.secretHash ?? DUMMY_HASH);
  return row && okShape && match ? row : null;
}

export async function pollView(db: DB, row: EnrollRow, now = new Date()) {
  const base = {
    request_id: row.id,
    status: row.status as EnrollStatus,
    request_code: row.requestCode,
    poll_interval_s: POLL_INTERVAL_S,
    expires_at: row.expiresAt.toISOString(),
    ...(row.status === 'rejected' && row.reason ? { reason: row.reason } : {}),
  };
  if (row.status !== 'approved' || !row.enrollKeyId) return base;
  if (row.claimedAt && now.getTime() - row.claimedAt.getTime() > CLAIM_WINDOW_MS) return base;
  if (!row.claimedAt && row.expiresAt.getTime() < now.getTime()) return base;
  const key = (await db.select({ revokedAt: enrollKeys.revokedAt }).from(enrollKeys).where(eq(enrollKeys.id, row.enrollKeyId)).limit(1))[0];
  if (!key || key.revokedAt) return base;
  const id = await hubIdentity(db);
  const clientKey = deriveClientKey(await credentialSecret(db), row.id, row.enrollKeyId);
  return {
    ...base,
    credentials: {
      agent_id: row.agentId,
      client_key: clientKey,
      hub_fingerprint: id.fingerprint,
      signature: sign(id, approvalMessage(row.id, row.agentId, clientKey)),
    },
  };
}

/** register 成功且用的是申請核准發的金鑰 → 記下領取時間（之後 10 分鐘就不再回憑證）。 */
export async function markClaimed(db: DB, enrollKeyId: string): Promise<void> {
  await db
    .update(enrollmentRequests)
    .set({ claimedAt: new Date() })
    .where(and(eq(enrollmentRequests.enrollKeyId, enrollKeyId), isNull(enrollmentRequests.claimedAt)));
}

// ---- 管理 ----

/** 管理頁看的欄位：絕不含 secret_hash、金鑰 id／雜湊或憑證。 */
export function publicRequest(r: EnrollRow, knownAgent: boolean) {
  return {
    id: r.id,
    status: r.status as EnrollStatus,
    agent_id: r.agentId,
    known_agent: knownAgent,
    hostname: r.hostname,
    os_family: r.osFamily,
    os_name: r.osName,
    os_version: r.osVersion,
    arch: r.arch,
    agent_version: r.agentVersion,
    ips: r.ips ?? [],
    source_ip: r.sourceIp,
    request_code: r.requestCode,
    accept_remote_actions: r.acceptRemoteActions,
    auto_approved: r.autoApproved,
    created_at: r.createdAt.toISOString(),
    decided_at: r.decidedAt?.toISOString() ?? null,
    decided_by: r.decidedBy,
    reason: r.reason,
    expires_at: r.expiresAt.toISOString(),
    claimed_at: r.claimedAt?.toISOString() ?? null,
  };
}
export type EnrollRequestView = ReturnType<typeof publicRequest>;

async function knownAgents(db: DB, ids: string[]): Promise<Set<string>> {
  if (!ids.length) return new Set();
  const rows = await db.select({ id: agents.id }).from(agents).where(and(inArray(agents.id, [...new Set(ids)]), isNull(agents.deletedAt)));
  return new Set(rows.map((r) => r.id));
}

async function views(db: DB, rows: EnrollRow[]): Promise<EnrollRequestView[]> {
  const known = await knownAgents(db, rows.map((r) => r.agentId));
  return rows.map((r) => publicRequest(r, known.has(r.agentId)));
}

/** 側欄徽章用：只讀不寫（過期的不算）。 */
export async function pendingCount(db: DB, now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - REQUEST_TTL_MS);
  const [{ n }] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(enrollmentRequests)
    .where(and(eq(enrollmentRequests.status, 'pending'), gte(enrollmentRequests.createdAt, cutoff)));
  return Number(n);
}

export async function listRequests(db: DB, opts: { status: 'pending' | 'all'; limit?: number }) {
  await expireStale(db);
  const q = db.select().from(enrollmentRequests);
  const rows = await (opts.status === 'pending' ? q.where(eq(enrollmentRequests.status, 'pending')) : q)
    .orderBy(desc(enrollmentRequests.createdAt))
    .limit(Math.min(opts.limit ?? 500, 500));
  const grouped = await db
    .select({ status: enrollmentRequests.status, n: sql<number>`count(*)::int` })
    .from(enrollmentRequests)
    .groupBy(enrollmentRequests.status);
  const counts: Record<EnrollStatus, number> = { pending: 0, approved: 0, rejected: 0, expired: 0 };
  for (const g0 of grouped) if ((STATUSES as readonly string[]).includes(g0.status)) counts[g0.status as EnrollStatus] = Number(g0.n);
  return { items: await views(db, rows), counts };
}

export async function decide(
  db: DB,
  ids: string[],
  decision: 'approve' | 'reject',
  meta: { actor: string; reason?: string | null; sourceIp: string },
): Promise<EnrollRequestView[]> {
  await expireStale(db);
  const changed: EnrollRow[] = [];
  for (const id of [...new Set(ids)]) {
    let row: EnrollRow | null;
    if (decision === 'approve') {
      row = await approveRow(db, id, meta.actor, { reason: meta.reason });
    } else {
      [row = null] = await db
        .update(enrollmentRequests)
        .set({ status: 'rejected', decidedAt: new Date(), decidedBy: meta.actor, reason: meta.reason ?? null })
        .where(and(eq(enrollmentRequests.id, id), eq(enrollmentRequests.status, 'pending')))
        .returning();
    }
    if (!row) continue;
    changed.push(row);
    await audit({
      actor: meta.actor,
      actorRole: 'admin',
      action: decision === 'approve' ? 'enroll_request.approved' : 'enroll_request.rejected',
      targetType: 'enrollment_request',
      targetId: row.id,
      sourceIp: meta.sourceIp,
      details: { agent_id: row.agentId, hostname: row.hostname, request_code: row.requestCode, ...(meta.reason ? { reason: meta.reason } : {}) },
    });
  }
  return views(db, changed);
}
