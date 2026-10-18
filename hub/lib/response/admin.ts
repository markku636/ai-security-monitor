// 自動回應與主機群組的管理：規則、群組（含成員）的新增／修改／刪除，與給網頁的檢視。
import { randomUUID } from 'node:crypto';
import { desc, eq, inArray } from 'drizzle-orm';
import { z } from 'zod';
import { agentGroupMembers, agentGroups, agents, responseBlocks, responseRules } from '@/drizzle/schema';
import { InputError, onlyGiven } from '@/lib/admin-write';
import type { DB } from '@/lib/db';
import { CentralConfig } from '@/lib/central/config';
import { TRIGGERS, getResponseSettings } from './engine';

export const MAX_RULES = 50;
export const MAX_GROUPS = 100;

const name = z.string().trim().min(1).max(80);

export const RuleBody = z.object({
  name,
  trigger: z.enum(TRIGGERS),
  params: z
    .object({
      threshold: z.number().int().min(3).max(10_000).optional(),
      rule: z
        .string()
        .trim()
        .max(120)
        .regex(/^[a-z0-9_.-]+\*?$/)
        .optional(),
    })
    .default({}),
  blockMinutes: z.number().int().min(5).max(7 * 24 * 60).default(60),
  escalate: z.boolean().default(true),
  groupId: z.string().max(64).nullish(),
  enabled: z.boolean().default(true),
});

export const GroupBody = z.object({
  name,
  description: z.string().trim().max(500).default(''),
  members: z.array(z.string().max(128)).max(5000).default([]),
  /** 集中設定（只接受安全的選項）。 */
  config: CentralConfig.default({}),
});

export async function responseView(db: DB) {
  const [settings, rules, blocks, groups, members, hosts] = await Promise.all([
    getResponseSettings(db),
    db.select().from(responseRules).orderBy(responseRules.createdAt),
    db.select({ b: responseBlocks, hostname: agents.hostname }).from(responseBlocks).innerJoin(agents, eq(agents.id, responseBlocks.agentId)).orderBy(desc(responseBlocks.blockedAt)).limit(100),
    db.select().from(agentGroups).orderBy(agentGroups.name),
    db.select().from(agentGroupMembers),
    db.select({ id: agents.id, hostname: agents.hostname, accept: agents.acceptRemoteActions, deletedAt: agents.deletedAt }).from(agents),
  ]);
  return {
    settings,
    rules: rules.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() })),
    blocks: blocks.map(({ b, hostname }) => ({
      id: b.id,
      ruleId: b.ruleId,
      agentId: b.agentId,
      hostname,
      ip: b.ip,
      reason: b.reason,
      level: b.level,
      status: b.status,
      blockedAt: b.blockedAt.toISOString(),
      expiresAt: b.expiresAt.toISOString(),
      releasedAt: b.releasedAt?.toISOString() ?? null,
    })),
    groups: groups.map((g) => ({ id: g.id, name: g.name, description: g.description, config: g.config, members: members.filter((m) => m.groupId === g.id).map((m) => m.agentId) })),
    hosts: hosts.filter((h) => !h.deletedAt).map((h) => ({ id: h.id, hostname: h.hostname, acceptsActions: h.accept })),
  };
}
export type ResponseView = Awaited<ReturnType<typeof responseView>>;

async function checkGroup(db: DB, id: string | null | undefined): Promise<void> {
  if (!id) return;
  const [g] = await db.select({ id: agentGroups.id }).from(agentGroups).where(eq(agentGroups.id, id)).limit(1);
  if (!g) throw new InputError('unknown_group');
}

function checkParams(trigger: string, params: { rule?: string }): void {
  if (trigger === 'finding' && !params.rule) throw new InputError('invalid_params.rule');
}

export async function createResponseRule(db: DB, input: unknown, actor: string): Promise<string> {
  const b = RuleBody.parse(input);
  checkParams(b.trigger, b.params);
  if ((await db.select({ id: responseRules.id }).from(responseRules)).length >= MAX_RULES) throw new InputError('too_many_rules');
  await checkGroup(db, b.groupId);
  const id = randomUUID();
  await db.insert(responseRules).values({ id, name: b.name, trigger: b.trigger, params: b.params, blockMinutes: b.blockMinutes, escalate: b.escalate, groupId: b.groupId || null, enabled: b.enabled, createdBy: actor });
  return id;
}

export async function updateResponseRule(db: DB, id: string, input: unknown): Promise<boolean> {
  const b = onlyGiven(RuleBody.partial().parse(input), input);
  const [cur] = await db.select().from(responseRules).where(eq(responseRules.id, id)).limit(1);
  if (!cur) return false;
  await checkGroup(db, b.groupId);
  const trigger = b.trigger ?? cur.trigger;
  const params = b.params ?? cur.params;
  checkParams(trigger, params as { rule?: string });
  const patch: Partial<typeof responseRules.$inferInsert> = {};
  for (const k of ['name', 'blockMinutes', 'escalate', 'enabled', 'params'] as const) if (b[k] !== undefined) (patch as Record<string, unknown>)[k] = b[k];
  if (b.groupId !== undefined) patch.groupId = b.groupId || null;
  // 換觸發條件＝新規則：從現在開始算
  if (b.trigger !== undefined && b.trigger !== cur.trigger) {
    patch.trigger = b.trigger;
    patch.createdAt = new Date();
  }
  if (Object.keys(patch).length) await db.update(responseRules).set(patch).where(eq(responseRules.id, id));
  return true;
}

export async function deleteResponseRule(db: DB, id: string): Promise<boolean> {
  return (await db.delete(responseRules).where(eq(responseRules.id, id)).returning({ id: responseRules.id })).length > 0;
}

async function setMembers(db: DB, groupId: string, members: string[]): Promise<void> {
  const uniq = [...new Set(members)];
  const known = uniq.length ? new Set((await db.select({ id: agents.id }).from(agents).where(inArray(agents.id, uniq))).map((a) => a.id)) : new Set<string>();
  if (uniq.some((m) => !known.has(m))) throw new InputError('unknown_agent');
  await db.delete(agentGroupMembers).where(eq(agentGroupMembers.groupId, groupId));
  if (uniq.length) await db.insert(agentGroupMembers).values(uniq.map((agentId) => ({ groupId, agentId })));
}

export async function createGroup(db: DB, input: unknown, actor: string): Promise<string> {
  const b = GroupBody.parse(input);
  if ((await db.select({ id: agentGroups.id }).from(agentGroups)).length >= MAX_GROUPS) throw new InputError('too_many_groups');
  const id = randomUUID();
  await db.insert(agentGroups).values({ id, name: b.name, description: b.description, config: b.config, createdBy: actor });
  await setMembers(db, id, b.members);
  return id;
}

export async function updateGroup(db: DB, id: string, input: unknown): Promise<boolean> {
  const b = onlyGiven(GroupBody.partial().parse(input), input);
  const [cur] = await db.select().from(agentGroups).where(eq(agentGroups.id, id)).limit(1);
  if (!cur) return false;
  const patch: Partial<typeof agentGroups.$inferInsert> = {};
  if (b.name !== undefined) patch.name = b.name;
  if (b.description !== undefined) patch.description = b.description;
  if (b.config !== undefined) patch.config = b.config;
  if (Object.keys(patch).length) await db.update(agentGroups).set(patch).where(eq(agentGroups.id, id));
  if (b.members !== undefined) await setMembers(db, id, b.members);
  return true;
}

export async function deleteGroup(db: DB, id: string): Promise<boolean> {
  const r = await db.delete(agentGroups).where(eq(agentGroups.id, id)).returning({ id: agentGroups.id });
  if (!r.length) return false;
  // 只套用到這個群組的規則：停用（不要默默變成套用到全部主機）
  await db.update(responseRules).set({ enabled: false, groupId: null }).where(eq(responseRules.groupId, id));
  return true;
}
