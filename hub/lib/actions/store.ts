// 遠端動作的狀態機與查詢。
//   pending ──approve──▶ approved ──agent 取走──▶ dispatched ──result──▶ succeeded／failed
//      │ reject／過期                │ cancel／過期           │ 逾時未回報 10 分鐘 → 重新派送（agent 端以 id 去重）
//      ▼                             ▼
//   rejected／expired             cancelled／expired
import crypto from 'node:crypto';
import { and, desc, eq, inArray, lt, or, sql, type SQL } from 'drizzle-orm';
import { actions, agents } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { KIND_INFO, parseAction } from './kinds';
import { actionKeyFor, paramsHash, signingKey, tokenFor } from './sign';

export const ACTION_STATUSES = ['pending', 'approved', 'dispatched', 'succeeded', 'failed', 'rejected', 'cancelled', 'expired'] as const;
export type ActionStatus = (typeof ACTION_STATUSES)[number];
const OPEN: ActionStatus[] = ['pending', 'approved', 'dispatched'];

export const PENDING_TTL_MS = 7 * 86_400_000;
export const APPROVED_TTL_MS = 24 * 3_600_000;
export const REDISPATCH_AFTER_MS = 10 * 60_000;
export const MAX_OUTPUT = 64 * 1024;

export type ActionRow = typeof actions.$inferSelect;
export type ActionError =
  | 'agent_not_found'
  | 'duplicate'
  | 'not_found'
  | 'bad_state'
  | 'expired'
  | 'agent_does_not_accept_actions'
  | 'confirm_hostname'
  | string;

function newId(): string {
  return `act_${crypto.randomBytes(8).toString('hex')}`;
}

/** 過期處理（每次讀寫前順手做，不另開排程）。 */
export async function expireStale(db: DB, now = new Date()): Promise<void> {
  await db
    .update(actions)
    .set({ status: 'expired' })
    .where(and(inArray(actions.status, OPEN), lt(actions.expiresAt, now)));
}

export async function createAction(
  db: DB,
  input: { agentId: string; kind: string; params: unknown; reason?: string; findingId?: string; proposedBy: string },
): Promise<{ action: ActionRow } | { error: ActionError }> {
  const parsed = parseAction(input.kind, input.params);
  if (!parsed.ok) return { error: parsed.error };
  const agent = (await db.select({ id: agents.id, deletedAt: agents.deletedAt }).from(agents).where(eq(agents.id, input.agentId)).limit(1))[0];
  if (!agent || agent.deletedAt) return { error: 'agent_not_found' };
  await expireStale(db);
  const hash = paramsHash(parsed.params);
  const open = await db
    .select({ id: actions.id })
    .from(actions)
    .where(and(eq(actions.agentId, input.agentId), eq(actions.kind, parsed.kind), eq(actions.paramsHash, hash), inArray(actions.status, OPEN)))
    .limit(1);
  if (open.length) return { error: 'duplicate' };
  const info = KIND_INFO[parsed.kind];
  try {
    const [row] = await db
      .insert(actions)
      .values({
        id: newId(),
        agentId: input.agentId,
        findingId: input.findingId ?? null,
        kind: parsed.kind,
        params: parsed.params,
        paramsHash: hash,
        reason: (input.reason ?? '').slice(0, 500),
        destructive: info.destructive,
        requiresElevation: info.requiresElevation,
        proposedBy: input.proposedBy,
        status: 'pending',
        expiresAt: new Date(Date.now() + PENDING_TTL_MS),
      })
      .returning();
    return { action: row };
  } catch {
    // 唯一索引擋下的同時建立
    return { error: 'duplicate' };
  }
}

export async function getAction(db: DB, id: string): Promise<ActionRow | null> {
  return (await db.select().from(actions).where(eq(actions.id, id)).limit(1))[0] ?? null;
}

export async function decideAction(
  db: DB,
  id: string,
  decision: 'approve' | 'reject' | 'cancel',
  opts: { by: string; note?: string; confirmHostname?: string },
): Promise<{ action: ActionRow } | { error: ActionError }> {
  await expireStale(db);
  const a = await getAction(db, id);
  if (!a) return { error: 'not_found' };
  const now = new Date();
  const note = opts.note?.slice(0, 500) ?? null;
  if (decision === 'approve' || decision === 'reject') {
    if (a.status === 'expired') return { error: 'expired' };
    if (a.status !== 'pending') return { error: 'bad_state' };
  } else if (a.status !== 'approved' && a.status !== 'dispatched') {
    return { error: 'bad_state' };
  }
  if (decision === 'approve') {
    const agent = (await db.select().from(agents).where(eq(agents.id, a.agentId)).limit(1))[0];
    if (!agent?.acceptRemoteActions) return { error: 'agent_does_not_accept_actions' };
    if (a.destructive && opts.confirmHostname?.trim() !== agent.hostname) return { error: 'confirm_hostname' };
  }
  const set =
    decision === 'approve'
      ? { status: 'approved', reviewedBy: opts.by, reviewedAt: now, reviewNote: note, expiresAt: new Date(now.getTime() + APPROVED_TTL_MS) }
      : decision === 'reject'
        ? { status: 'rejected', reviewedBy: opts.by, reviewedAt: now, reviewNote: note }
        : { status: 'cancelled', reviewNote: note ?? a.reviewNote };
  // 以目前狀態為條件更新，避免與 agent 取走／回報競爭。
  const [row] = await db
    .update(actions)
    .set(set)
    .where(and(eq(actions.id, id), eq(actions.status, a.status)))
    .returning();
  return row ? { action: row } : { error: 'bad_state' };
}

export interface ListActionsFilter {
  status?: ActionStatus[];
  agentId?: string;
  limit?: number;
  offset?: number;
}

export async function listActions(db: DB, f: ListActionsFilter = {}) {
  await expireStale(db);
  const conds: SQL[] = [];
  if (f.status?.length) conds.push(inArray(actions.status, f.status));
  if (f.agentId) conds.push(eq(actions.agentId, f.agentId));
  const where = conds.length ? and(...conds) : undefined;
  const [items, counts] = await Promise.all([
    db
      .select({ a: actions, hostname: agents.hostname, acceptRemoteActions: agents.acceptRemoteActions })
      .from(actions)
      .innerJoin(agents, eq(agents.id, actions.agentId))
      .where(where)
      .orderBy(sql`case ${actions.status} when 'pending' then 0 when 'approved' then 1 when 'dispatched' then 2 else 3 end`, desc(actions.createdAt))
      .limit(Math.min(f.limit ?? 100, 200))
      .offset(f.offset ?? 0),
    db
      .select({ k: actions.status, n: sql<number>`count(*)::int` })
      .from(actions)
      .where(f.agentId ? eq(actions.agentId, f.agentId) : undefined)
      .groupBy(actions.status),
  ]);
  return {
    items: items.map((r) => ({ ...r.a, hostname: r.hostname, agentAccepts: r.acceptRemoteActions })),
    counts: Object.fromEntries(counts.map((c) => [c.k, Number(c.n)])) as Record<string, number>,
  };
}

/** 要交給 agent 的動作：已核准、或派送後 10 分鐘沒回報的；附 HMAC token。 */
export async function dispatchForAgent(db: DB, agentId: string) {
  await expireStale(db);
  const now = new Date();
  const rows = await db
    .select()
    .from(actions)
    .where(
      and(
        eq(actions.agentId, agentId),
        or(
          eq(actions.status, 'approved'),
          and(eq(actions.status, 'dispatched'), lt(actions.dispatchedAt, new Date(now.getTime() - REDISPATCH_AFTER_MS))),
        ),
      ),
    )
    .orderBy(actions.reviewedAt)
    .limit(20);
  if (!rows.length) return [];
  const key = actionKeyFor(await signingKey(db), agentId);
  await db
    .update(actions)
    .set({ status: 'dispatched', dispatchedAt: now })
    .where(inArray(actions.id, rows.map((r) => r.id)));
  return rows.map((r) => {
    const fields = { action_id: r.id, agent_id: r.agentId, kind: r.kind, params: r.params, expires_at: r.expiresAt.toISOString() };
    return { ...fields, reason: r.reason, destructive: r.destructive, token: tokenFor(key, fields) };
  });
}

export async function recordResult(
  db: DB,
  agentId: string,
  id: string,
  result: { ok: boolean; output: string },
): Promise<{ action: ActionRow } | { error: ActionError }> {
  const a = await getAction(db, id);
  if (!a || a.agentId !== agentId) return { error: 'not_found' };
  // 取消或過期後才回報：仍記下真實結果（agent 可能在取消前就執行了）。
  if (!['dispatched', 'approved', 'cancelled', 'expired'].includes(a.status)) return { error: 'bad_state' };
  const [row] = await db
    .update(actions)
    .set({
      status: result.ok ? 'succeeded' : 'failed',
      completedAt: new Date(),
      resultOk: result.ok,
      resultOutput: result.output.slice(0, MAX_OUTPUT),
    })
    .where(eq(actions.id, id))
    .returning();
  return { action: row };
}

export async function openActionCount(db: DB, agentId: string): Promise<number> {
  const r = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(actions)
    .where(and(eq(actions.agentId, agentId), eq(actions.status, 'approved')));
  return Number(r[0]?.n ?? 0);
}
