// 自動回應：依規則找出攻擊來源 IP，替「已同意遠端動作」的主機自動建立並核准 block_ip（有到期時間），到期再自動 unblock_ip。
// 安全護欄：全域開關預設關；只封公網 IP；私有／保留位址與白名單網段一律不封；同一台主機同一個 IP 同時只有一筆封鎖；
// 每輪最多新增 MAX_NEW_PER_RUN 筆；每一步都寫稽核。重複觸犯（30 天內）封鎖時間 ×6、×24。
import { randomUUID } from 'node:crypto';
import { and, count, eq, gt, gte, inArray, isNull, lt, sql } from 'drizzle-orm';
import { agentGroupMembers, agents, connections, findings, reports, responseBlocks, responseRules, securityEvents, settings } from '@/drizzle/schema';
import { createAction, decideAction } from '@/lib/actions/store';
import { audit } from '@/lib/audit';
import type { DB } from '@/lib/db';
import { matchCidr, normalizeCidrList } from '@/lib/enroll/cidr';
import { isPublicIp, normalizeIp } from '@/lib/ipintel/ip';

export const TRIGGERS = ['intel_inbound', 'bruteforce', 'finding'] as const;
export type Trigger = (typeof TRIGGERS)[number];

const SETTINGS_KEY = 'response.settings';
const LOOKBACK_MS = 24 * 3600_000;
export const MAX_NEW_PER_RUN = 50;
const REPEAT_WINDOW_MS = 30 * 86_400_000;
const ESCALATION = [1, 6, 24];

export interface ResponseSettings {
  enabled: boolean;
  /** 永遠不封的網段（例：公司對外 IP、合作夥伴）。 */
  allowlist: string[];
}

export async function getResponseSettings(db: DB): Promise<ResponseSettings> {
  const [row] = await db.select().from(settings).where(eq(settings.key, SETTINGS_KEY)).limit(1);
  const v = (row?.value ?? {}) as Partial<ResponseSettings>;
  const list = normalizeCidrList(Array.isArray(v.allowlist) ? v.allowlist : []);
  return { enabled: v.enabled === true, allowlist: Array.isArray(list) ? list : [] };
}

export async function saveResponseSettings(db: DB, s: ResponseSettings, actor: string): Promise<void> {
  await db
    .insert(settings)
    .values({ key: SETTINGS_KEY, value: s, updatedBy: actor })
    .onConflictDoUpdate({ target: settings.key, set: { value: s, updatedAt: new Date(), updatedBy: actor } });
}

type Rule = typeof responseRules.$inferSelect;

interface Candidate {
  agentId: string;
  ip: string;
  reason: string;
}

/** 規則的 finding 樣式：完整名稱或結尾 *。 */
export function ruleMatches(pattern: string, rule: string): boolean {
  return pattern.endsWith('*') ? rule.startsWith(pattern.slice(0, -1)) : rule === pattern;
}

async function candidates(db: DB, rule: Rule, now: Date): Promise<Candidate[]> {
  const since = new Date(Math.max(rule.createdAt.getTime(), now.getTime() - LOOKBACK_MS));
  switch (rule.trigger as Trigger) {
    case 'intel_inbound': {
      // 最新快照裡、被情資列名的來源連進來的連線
      const rows = await db
        .select({ agentId: connections.agentId, ip: connections.remoteIp, feeds: connections.intelFeedIds })
        .from(connections)
        .where(and(eq(connections.direction, 'inbound'), sql`jsonb_array_length(${connections.intelFeedIds}) > 0`, gte(connections.at, since)))
        .limit(500);
      return rows.filter((r) => r.ip).map((r) => ({ agentId: r.agentId, ip: r.ip!, reason: `intel: ${(r.feeds ?? []).slice(0, 3).join(', ')}` }));
    }
    case 'bruteforce': {
      const threshold = Math.max(3, Number(rule.params?.threshold) || 10);
      const rows = await db
        .select({ agentId: securityEvents.agentId, ip: securityEvents.sourceIp, n: securityEvents.count, rule: securityEvents.rule })
        .from(securityEvents)
        .where(
          and(
            inArray(securityEvents.rule, ['failed_logon_burst', 'ntlm_failure_burst']),
            sql`${securityEvents.sourceIp} is not null`,
            sql`${securityEvents.count} >= ${threshold}`,
            gte(securityEvents.lastAt, since),
          ),
        )
        .limit(500);
      return rows.map((r) => ({ agentId: r.agentId, ip: r.ip!, reason: `${r.rule} ×${r.n}` }));
    }
    case 'finding': {
      const pattern = String(rule.params?.rule ?? '').trim();
      if (!pattern) return [];
      const rows = await db
        .select({ agentId: findings.agentId, ip: findings.indicator, rule: findings.rule })
        .from(findings)
        .innerJoin(reports, eq(reports.id, findings.firstReportId))
        .where(and(eq(findings.status, 'open'), sql`${findings.indicator} is not null`, gte(reports.receivedAt, since)))
        .limit(1000);
      return rows.filter((r) => ruleMatches(pattern, r.rule)).map((r) => ({ agentId: r.agentId, ip: r.ip!, reason: r.rule }));
    }
    default:
      return [];
  }
}

export interface ResponseRun {
  blocked: number;
  released: number;
  skipped: number;
}

/** 一輪：先解除到期的，再處理新的。關閉時只做解除（關掉開關不會讓已封的 IP 永遠封著）。 */
export async function runAutoResponse(db: DB, now = new Date()): Promise<ResponseRun> {
  const out: ResponseRun = { blocked: 0, released: 0, skipped: 0 };
  const due = await db
    .select()
    .from(responseBlocks)
    .where(and(eq(responseBlocks.status, 'active'), lt(responseBlocks.expiresAt, now)))
    .limit(200);
  for (const b of due) if (await release(db, b.id, 'system:expired', now)) out.released++;

  const s = await getResponseSettings(db);
  if (!s.enabled) return out;
  const rules = await db.select().from(responseRules).where(eq(responseRules.enabled, true));
  if (!rules.length) return out;
  // 只對同意遠端動作、沒有被刪除的主機
  const okAgents = new Map(
    (await db.select({ id: agents.id, accept: agents.acceptRemoteActions, deletedAt: agents.deletedAt }).from(agents).where(isNull(agents.deletedAt)))
      .filter((a) => a.accept)
      .map((a) => [a.id, true]),
  );
  const active = new Set(
    (await db.select({ a: responseBlocks.agentId, ip: responseBlocks.ip }).from(responseBlocks).where(eq(responseBlocks.status, 'active'))).map((r) => `${r.a}|${r.ip}`),
  );
  let created = 0;
  for (const rule of rules) {
    const members = rule.groupId
      ? new Set((await db.select({ id: agentGroupMembers.agentId }).from(agentGroupMembers).where(eq(agentGroupMembers.groupId, rule.groupId))).map((r) => r.id))
      : null;
    for (const c of await candidates(db, rule, now)) {
      if (created >= MAX_NEW_PER_RUN) return out;
      const ip = normalizeIp(c.ip);
      const k = `${c.agentId}|${ip}`;
      if (active.has(k) || !okAgents.has(c.agentId) || (members && !members.has(c.agentId))) continue;
      if (!isPublicIp(ip) || matchCidr(ip, s.allowlist)) {
        out.skipped++;
        continue;
      }
      const [prev] = await db
        .select({ n: count() })
        .from(responseBlocks)
        .where(and(eq(responseBlocks.agentId, c.agentId), eq(responseBlocks.ip, ip), gt(responseBlocks.blockedAt, new Date(now.getTime() - REPEAT_WINDOW_MS))));
      const level = rule.escalate ? Math.min(Number(prev?.n ?? 0), ESCALATION.length - 1) : 0;
      const minutes = rule.blockMinutes * ESCALATION[level];
      const by = `auto:${rule.id}`;
      const made = await createAction(db, {
        agentId: c.agentId,
        kind: 'block_ip',
        params: { ip, direction: 'both', reason: `auto-response: ${rule.name}` },
        reason: `${rule.name}：${c.reason}`,
        proposedBy: by,
      });
      if ('error' in made) {
        out.skipped++;
        continue;
      }
      const ok = await decideAction(db, made.action.id, 'approve', { by, note: `auto-response ${minutes} min` });
      if ('error' in ok) {
        out.skipped++;
        continue;
      }
      const id = randomUUID();
      await db.insert(responseBlocks).values({
        id,
        ruleId: rule.id,
        agentId: c.agentId,
        ip,
        reason: c.reason.slice(0, 300),
        level,
        blockedAt: now,
        expiresAt: new Date(now.getTime() + minutes * 60_000),
        blockActionId: made.action.id,
      });
      await audit({ actor: by, actorRole: 'system', action: 'response.blocked', targetType: 'agent', targetId: c.agentId, details: { ip, rule: rule.name, minutes, level, reason: c.reason } });
      active.add(k);
      created++;
      out.blocked++;
    }
  }
  return out;
}

/** 解除一筆封鎖：建立並核准 unblock_ip。回傳是否有做事。 */
export async function release(db: DB, blockId: string, by: string, now = new Date()): Promise<boolean> {
  const [b] = await db.select().from(responseBlocks).where(and(eq(responseBlocks.id, blockId), eq(responseBlocks.status, 'active'))).limit(1);
  if (!b) return false;
  let unblockId: string | null = null;
  const made = await createAction(db, { agentId: b.agentId, kind: 'unblock_ip', params: { ip: b.ip }, reason: 'auto-response: expired', proposedBy: by });
  if (!('error' in made)) {
    const ok = await decideAction(db, made.action.id, 'approve', { by, note: 'auto-response release' });
    if (!('error' in ok)) unblockId = made.action.id;
  }
  await db.update(responseBlocks).set({ status: 'released', releasedAt: now, unblockActionId: unblockId }).where(eq(responseBlocks.id, b.id));
  await audit({ actor: by, actorRole: by.startsWith('system') ? 'system' : 'admin', action: 'response.released', targetType: 'agent', targetId: b.agentId, details: { ip: b.ip, unblock_action: unblockId } });
  return true;
}
