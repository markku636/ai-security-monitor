// 通知設定的管理：頻道與規則的新增／修改／刪除（驗證＋加密），以及給網頁的檢視（祕密遮罩）。
import { randomUUID } from 'node:crypto';
import { desc, eq } from 'drizzle-orm';
import { z } from 'zod';
import { notificationChannels, notificationLog, notificationRules, notificationSeen } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { CHANNEL_KINDS, maskConfig, prepareConfig, targetOf, type ChannelKind } from './channels';
import { secretKey } from './secret';
import { EVENTS, SEVERITY_ORDER, getNotifySettings } from './service';

export const MAX_CHANNELS = 50;
export const MAX_RULES = 100;

const name = z.string().trim().min(1).max(80);

export const ChannelBody = z.object({
  kind: z.enum(CHANNEL_KINDS),
  name,
  enabled: z.boolean().default(true),
  config: z.record(z.string(), z.unknown()),
});

export const ChannelPatch = z.object({
  name: name.optional(),
  enabled: z.boolean().optional(),
  config: z.record(z.string(), z.unknown()).optional(),
});

export const RuleBody = z.object({
  name,
  event: z.enum(EVENTS),
  minSeverity: z.enum(SEVERITY_ORDER).nullish(),
  agentId: z.string().max(128).nullish(),
  channelIds: z.array(z.string().max(64)).min(1).max(20),
  params: z
    .object({ minutes: z.number().int().min(5).max(7 * 24 * 60).optional(), hour: z.number().int().min(0).max(23).optional() })
    .default({}),
  enabled: z.boolean().default(true),
});

export const RulePatch = RuleBody.partial();

export class NotifyInputError extends Error {
  constructor(public code: string) {
    super(code);
  }
}

export async function notifyView(db: DB) {
  const key = await secretKey(db);
  const [channels, rules, log, s] = await Promise.all([
    db.select().from(notificationChannels).orderBy(notificationChannels.createdAt),
    db.select().from(notificationRules).orderBy(notificationRules.createdAt),
    db.select().from(notificationLog).orderBy(desc(notificationLog.id)).limit(30),
    getNotifySettings(db),
  ]);
  return {
    settings: s,
    channels: channels.map((c) => {
      const masked = maskConfig(c.kind as ChannelKind, c.config, key);
      return {
        id: c.id,
        kind: c.kind,
        name: c.name,
        enabled: c.enabled,
        config: masked,
        target: targetOf(c.kind as ChannelKind, masked),
        lastOkAt: c.lastOkAt?.toISOString() ?? null,
        lastError: c.lastError,
        lastErrorAt: c.lastErrorAt?.toISOString() ?? null,
      };
    }),
    rules: rules.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() })),
    log: log.map((l) => ({
      id: l.id,
      ruleId: l.ruleId,
      channelId: l.channelId,
      event: l.event,
      title: l.title,
      status: l.status,
      attempts: l.attempts,
      error: l.error,
      createdAt: l.createdAt.toISOString(),
      sentAt: l.sentAt?.toISOString() ?? null,
    })),
  };
}
export type NotifyView = Awaited<ReturnType<typeof notifyView>>;

function zodCode(e: unknown): string {
  return e instanceof z.ZodError ? `invalid_${e.issues[0]?.path.join('.') || 'config'}` : 'bad_request';
}

export async function createChannel(db: DB, input: unknown, actor: string): Promise<string> {
  const b = ChannelBody.parse(input);
  const existing = await db.select({ id: notificationChannels.id }).from(notificationChannels);
  if (existing.length >= MAX_CHANNELS) throw new NotifyInputError('too_many_channels');
  let config: Record<string, unknown>;
  try {
    config = prepareConfig(b.kind, b.config, await secretKey(db));
  } catch (e) {
    throw new NotifyInputError(zodCode(e));
  }
  const id = randomUUID();
  await db.insert(notificationChannels).values({ id, kind: b.kind, name: b.name, enabled: b.enabled, config, createdBy: actor });
  return id;
}

export async function updateChannel(db: DB, id: string, input: unknown): Promise<boolean> {
  const b = ChannelPatch.parse(input);
  const [cur] = await db.select().from(notificationChannels).where(eq(notificationChannels.id, id)).limit(1);
  if (!cur) return false;
  const patch: Partial<typeof notificationChannels.$inferInsert> = {};
  if (b.name !== undefined) patch.name = b.name;
  if (b.enabled !== undefined) patch.enabled = b.enabled;
  if (b.config !== undefined) {
    try {
      patch.config = prepareConfig(cur.kind as ChannelKind, b.config, await secretKey(db), cur.config);
    } catch (e) {
      throw new NotifyInputError(zodCode(e));
    }
  }
  if (Object.keys(patch).length) await db.update(notificationChannels).set(patch).where(eq(notificationChannels.id, id));
  return true;
}

export async function deleteChannel(db: DB, id: string): Promise<boolean> {
  const r = await db.delete(notificationChannels).where(eq(notificationChannels.id, id)).returning({ id: notificationChannels.id });
  if (!r.length) return false;
  // 規則裡拿掉這個頻道；待送的訊息一併刪
  for (const rule of await db.select().from(notificationRules)) {
    if (rule.channelIds.includes(id)) await db.update(notificationRules).set({ channelIds: rule.channelIds.filter((c) => c !== id) }).where(eq(notificationRules.id, rule.id));
  }
  await db.delete(notificationLog).where(eq(notificationLog.channelId, id));
  return true;
}

async function checkChannels(db: DB, ids: string[]): Promise<void> {
  const known = new Set((await db.select({ id: notificationChannels.id }).from(notificationChannels)).map((c) => c.id));
  if (ids.some((c) => !known.has(c))) throw new NotifyInputError('unknown_channel');
}

export async function createRule(db: DB, input: unknown, actor: string): Promise<string> {
  const b = RuleBody.parse(input);
  if ((await db.select({ id: notificationRules.id }).from(notificationRules)).length >= MAX_RULES) throw new NotifyInputError('too_many_rules');
  await checkChannels(db, b.channelIds);
  const id = randomUUID();
  await db.insert(notificationRules).values({
    id,
    name: b.name,
    event: b.event,
    minSeverity: b.event === 'finding' ? (b.minSeverity ?? 'high') : null,
    agentId: b.agentId || null,
    channelIds: [...new Set(b.channelIds)],
    params: b.params,
    enabled: b.enabled,
    createdBy: actor,
  });
  return id;
}

export async function updateRule(db: DB, id: string, input: unknown): Promise<boolean> {
  const b = RulePatch.parse(input);
  const [cur] = await db.select().from(notificationRules).where(eq(notificationRules.id, id)).limit(1);
  if (!cur) return false;
  if (b.channelIds) await checkChannels(db, b.channelIds);
  const patch: Partial<typeof notificationRules.$inferInsert> = {};
  if (b.name !== undefined) patch.name = b.name;
  if (b.enabled !== undefined) patch.enabled = b.enabled;
  if (b.channelIds !== undefined) patch.channelIds = [...new Set(b.channelIds)];
  if (b.minSeverity !== undefined) patch.minSeverity = b.minSeverity ?? null;
  if (b.agentId !== undefined) patch.agentId = b.agentId || null;
  if (b.params !== undefined) patch.params = b.params;
  // 改事件種類＝新規則：從現在開始算，不補發以前的
  if (b.event !== undefined && b.event !== cur.event) {
    patch.event = b.event;
    patch.createdAt = new Date();
    await db.delete(notificationSeen).where(eq(notificationSeen.ruleId, id));
  }
  if (Object.keys(patch).length) await db.update(notificationRules).set(patch).where(eq(notificationRules.id, id));
  return true;
}

export async function deleteRule(db: DB, id: string): Promise<boolean> {
  const r = await db.delete(notificationRules).where(eq(notificationRules.id, id)).returning({ id: notificationRules.id });
  if (!r.length) return false;
  await db.delete(notificationSeen).where(eq(notificationSeen.ruleId, id));
  return true;
}
