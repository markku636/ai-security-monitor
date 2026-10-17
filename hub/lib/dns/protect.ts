// 防護 DNS（Hub 端）：設定（settings 表 dns_protect）、dns-server 的身分、下發設定（ETag）、心跳、查詢紀錄寫入與統計。
// 關掉或暫停時 dns-server 照常轉送（只是不封鎖），正在用它的裝置不會斷網。
import crypto from 'node:crypto';
import net from 'node:net';
import { and, desc, eq, gte, isNull, sql } from 'drizzle-orm';
import { z } from 'zod';
import { agents, apiTokens, dnsResolverQueries, dnsServers, settings } from '@/drizzle/schema';
import { boundToOtherAgent, hasScope, type Identity } from '@/lib/auth/access';
import type { DB } from '@/lib/db';
import { env } from '@/lib/env';
import { agentTokenOf, pinAgentToken } from '@/lib/ingest/identity';
import { DnsRecordIn, MAX_DNS_RECORDS } from '@/lib/ingest/schema';
import { loadRegistry } from '@/lib/intel/registry';
import { fallbackRegistrable } from './apply';

export const PROTECT_KEY = 'dns_protect';
/** 超過這麼久沒心跳就當作離線（dns-server 每 30 秒送一次）。 */
export const SERVER_STALE_MS = 3 * 60_000;
/** dns-server 沒指定上游時用的（跟 agent 端的預設一致，只給畫面顯示）。 */
export const DEFAULT_UPSTREAMS = ['https://dns.quad9.net/dns-query', 'https://cloudflare-dns.com/dns-query'];
export const MAX_PAUSE_MINUTES = 24 * 60;

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{1,63}$/;
const domain = z
  .string()
  .trim()
  .toLowerCase()
  .transform((s) => s.replace(/^\*\./, '').replace(/\.$/, ''))
  .pipe(z.string().regex(DOMAIN_RE));

/** 上游：https:// 開頭（DoH）或 IP（可帶 port，IPv6 要加中括號）。 */
export function validUpstream(s: string): boolean {
  if (/^https:\/\/[a-z0-9.-]+(?::\d{1,5})?\/[^\s]*$/i.test(s)) return true;
  if (net.isIP(s)) return true;
  const v4 = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(s);
  if (v4) return net.isIPv4(v4[1]!) && Number(v4[2]) <= 65535;
  const v6 = /^\[([0-9a-f:.]+)\]:(\d{1,5})$/i.exec(s);
  return !!v6 && net.isIPv6(v6[1]!) && Number(v6[2]) <= 65535;
}

export const ProtectSettings = z.object({
  /** 封鎖開關（關＝dns-server 只轉送）。 */
  enabled: z.boolean().default(false),
  paused_until: z.string().datetime({ offset: true }).nullable().default(null),
  /** 空＝dns-server 的預設（Quad9 與 Cloudflare 的 DoH）。 */
  upstreams: z.array(z.string().trim().max(200).refine(validUpstream, 'upstream')).max(8).default([]),
  /** 指定拿來封鎖的網域情資（空＝自動挑已啟用、信心夠高、可商用的）。 */
  feeds: z.array(z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/)).max(32).default([]),
  min_confidence: z.number().int().min(40).max(100).default(75),
  block: z.array(domain).max(5000).default([]),
  allow: z.array(domain).max(5000).default([]),
  internal_suffixes: z.array(domain).max(50).default([]),
  block_private_relay: z.boolean().default(false),
  log: z.boolean().default(true),
});
export type ProtectSettingsT = z.infer<typeof ProtectSettings>;

export function defaultProtect(): ProtectSettingsT {
  return ProtectSettings.parse({});
}

export async function getProtect(db: DB): Promise<ProtectSettingsT> {
  const row = (await db.select().from(settings).where(eq(settings.key, PROTECT_KEY)).limit(1))[0];
  const p = ProtectSettings.safeParse(row?.value ?? {});
  return p.success ? p.data : defaultProtect();
}

async function save(db: DB, v: ProtectSettingsT, actor: string): Promise<void> {
  await db
    .insert(settings)
    .values({ key: PROTECT_KEY, value: v, updatedBy: actor })
    .onConflictDoUpdate({ target: settings.key, set: { value: v, updatedBy: actor, updatedAt: new Date() } });
}

/** 更新設定（只改有送的欄位）；格式錯回 `{ error }`。 */
export async function setProtect(
  db: DB,
  input: unknown,
  actor: string,
): Promise<{ before: ProtectSettingsT; after: ProtectSettingsT } | { error: string }> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { error: 'bad_request' };
  const before = await getProtect(db);
  const merged = ProtectSettings.safeParse({ ...before, ...(input as Record<string, unknown>) });
  if (!merged.success) return { error: `invalid:${merged.error.issues[0]?.path.join('.') ?? ''}` };
  const after = { ...merged.data, block: [...new Set(merged.data.block)], allow: [...new Set(merged.data.allow)] };
  await save(db, after, actor);
  return { before, after };
}

/** 暫停封鎖 N 分鐘（0＝立刻恢復）。 */
export async function pauseProtect(db: DB, minutes: number, actor: string, now = new Date()): Promise<ProtectSettingsT> {
  const cur = await getProtect(db);
  const m = Math.max(0, Math.min(MAX_PAUSE_MINUTES, Math.floor(minutes)));
  const next = { ...cur, paused_until: m > 0 ? new Date(now.getTime() + m * 60_000).toISOString() : null };
  await save(db, next, actor);
  return next;
}

export function isPaused(s: ProtectSettingsT, now = new Date()): boolean {
  return !!s.paused_until && Date.parse(s.paused_until) > now.getTime();
}

/** 下發給 dns-server 的設定；etag 依內容（暫停到期會讓 blocking 改變，etag 跟著變）。 */
export function serverConfig(s: ProtectSettingsT, now = new Date()) {
  const body = {
    blocking: s.enabled && !isPaused(s, now),
    enabled: s.enabled,
    paused_until: isPaused(s, now) ? s.paused_until : null,
    upstreams: s.upstreams,
    feeds: s.feeds,
    min_confidence: s.min_confidence,
    block: s.block,
    allow: s.allow,
    internal_suffixes: s.internal_suffixes,
    block_private_relay: s.block_private_relay,
    log: s.log,
  };
  const etag = `"${crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex').slice(0, 32)}"`;
  return { ...body, etag };
}

/** 可以拿來封鎖的網域情資（設定頁的選項）：自動挑選的條件跟 agent 端 dnsd::lists 一樣。 */
export function domainFeedOptions(minConfidence: number) {
  return loadRegistry()
    .filter((f) => f.kind === 'domain')
    .map((f) => ({
      id: f.id,
      name: f.name,
      confidence: f.confidence,
      license: f.license.name,
      commercial_ok: f.license.commercial_ok,
      enabled_default: f.enabled_default,
      auto: f.enabled_default && f.confidence >= minConfidence && f.license.commercial_ok,
    }));
}

export interface DnsServerWho {
  id: string;
  name: string;
  agentId: string | null;
}

/**
 * 呼叫者是哪一台防護 DNS：dns 權杖（網頁建立的或 compose 的 ASA_HUB_DNS_TOKEN），或由背景服務帶起的 dns-server
 * 用那台電腦的 client 金鑰（X-ASA-Agent-Id，要通過身分釘選）。其他身分 → null。
 */
export async function dnsServerOf(id: Identity, req: Request, db: DB): Promise<DnsServerWho | null> {
  if (hasScope(id, 'dns')) {
    if (id.tokenId === 'env') return { id: 'env', name: 'compose', agentId: null };
    const t = (await db.select({ name: apiTokens.name }).from(apiTokens).where(eq(apiTokens.id, id.tokenId ?? '')).limit(1))[0];
    return { id: `token:${id.tokenId}`, name: t?.name ?? `token ${id.tokenId}`, agentId: null };
  }
  if (id.role !== 'client') return null;
  const agentId = req.headers.get('x-asa-agent-id')?.trim() ?? '';
  if (!agentId || boundToOtherAgent(id, agentId)) return null;
  const a = (await db.select({ hostname: agents.hostname, deletedAt: agents.deletedAt }).from(agents).where(eq(agents.id, agentId)).limit(1))[0];
  if (!a || a.deletedAt) return null;
  const pin = await pinAgentToken(db, agentId, agentTokenOf(req));
  if (pin === 'mismatch' || pin === 'unknown_agent') return null;
  return { id: `agent:${agentId}`, name: a.hostname, agentId };
}

export const ServerHeartbeat = z
  .object({
    version: z.string().max(40).default(''),
    hostname: z.string().max(255).default(''),
    status: z.record(z.string(), z.unknown()).default({}),
  })
  .passthrough();
export type ServerHeartbeatT = z.infer<typeof ServerHeartbeat>;

async function upsertServer(db: DB, who: DnsServerWho, patch: Partial<typeof dnsServers.$inferInsert>, now: Date) {
  await db
    .insert(dnsServers)
    .values({ id: who.id, name: who.name, agentId: who.agentId, firstSeenAt: now, lastSeenAt: now, ...patch })
    .onConflictDoUpdate({ target: dnsServers.id, set: { name: who.name, agentId: who.agentId, lastSeenAt: now, ...patch } });
}

export async function recordHeartbeat(db: DB, who: DnsServerWho, hb: ServerHeartbeatT, ip: string, now = new Date()): Promise<void> {
  // 狀態只留需要的欄位、限制大小（不信任送來的內容）
  const status = JSON.parse(JSON.stringify(hb.status, (_k, v) => (typeof v === 'string' ? v.slice(0, 300) : v))) as Record<string, unknown>;
  if (JSON.stringify(status).length > 32 * 1024) throw new Error('status_too_large');
  await upsertServer(db, who, { version: hb.version, hostname: hb.hostname, sourceIp: ip, status }, now);
}

export const ResolverRecord = DnsRecordIn.extend({ client: z.string().max(64).refine((s) => net.isIP(s) > 0, 'client') });
export const ResolverBatch = z
  .object({
    records: z.array(ResolverRecord).min(1).max(MAX_DNS_RECORDS),
  })
  .passthrough();
export type ResolverBatchT = z.infer<typeof ResolverBatch>;

/** 用戶端 IP → 主機（只取對得到唯一一台、沒被刪除的）。 */
async function clientAgents(db: DB): Promise<Map<string, string>> {
  const rows = await db.select({ id: agents.id, ips: agents.ips }).from(agents).where(isNull(agents.deletedAt));
  const seen = new Map<string, string | null>();
  for (const r of rows) {
    for (const ip of r.ips ?? []) {
      const k = ip.toLowerCase();
      seen.set(k, seen.has(k) && seen.get(k) !== r.id ? null : r.id);
    }
  }
  const out = new Map<string, string>();
  for (const [k, v] of seen) if (v) out.set(k, v);
  return out;
}

export async function applyResolver(db: DB, who: DnsServerWho, b: ResolverBatchT, now = new Date()) {
  await upsertServer(db, who, {}, now);
  const map = await clientAgents(db);
  const oldest = now.getTime() - env().dnsRawDays * 86_400_000;
  let stale = 0;
  const rows = new Map<string, typeof dnsResolverQueries.$inferInsert>();
  for (const r of b.records) {
    let t = Date.parse(r.ts);
    if (t < oldest) {
      stale++;
      continue;
    }
    if (t > now.getTime()) t = now.getTime();
    const name = r.name.toLowerCase().replace(/\.$/, '');
    const client = r.client.toLowerCase();
    rows.set([t, client, name, r.qtype, r.rcode].join('|'), {
      serverId: who.id,
      ts: new Date(t),
      client,
      agentId: map.get(client) ?? null,
      name,
      registrable: (r.registrable || fallbackRegistrable(name)).toLowerCase(),
      qtype: r.qtype,
      rcode: r.rcode,
      blockedBy: r.rcode === 'BLOCKED' ? (r.process ?? '').slice(0, 120) : '',
      count: r.count,
      answers: r.answers,
      receivedAt: now,
    });
  }
  const list = [...rows.values()];
  for (let i = 0; i < list.length; i += 200) {
    await db
      .insert(dnsResolverQueries)
      .values(list.slice(i, i + 200))
      .onConflictDoUpdate({
        target: [dnsResolverQueries.serverId, dnsResolverQueries.ts, dnsResolverQueries.client, dnsResolverQueries.name, dnsResolverQueries.qtype, dnsResolverQueries.rcode],
        set: { count: sql`excluded.count`, answers: sql`excluded.answers`, agentId: sql`excluded.agent_id`, receivedAt: now },
      });
  }
  return { stored: list.length, stale, mapped: list.filter((r) => r.agentId).length };
}

export async function listServers(db: DB, now = new Date()) {
  const rows = await db.select().from(dnsServers).orderBy(desc(dnsServers.lastSeenAt)).limit(50);
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    agentId: r.agentId,
    version: r.version,
    hostname: r.hostname,
    sourceIp: r.sourceIp,
    status: r.status,
    firstSeenAt: r.firstSeenAt.toISOString(),
    lastSeenAt: r.lastSeenAt.toISOString(),
    online: now.getTime() - r.lastSeenAt.getTime() < SERVER_STALE_MS,
  }));
}

/** 最近 N 小時：查詢、封鎖、用戶端數、被擋最多的網域、用量最多的用戶端。 */
export async function resolverStats(db: DB, hours = 24, now = new Date()) {
  const since = new Date(now.getTime() - hours * 3_600_000);
  const where = gte(dnsResolverQueries.ts, since);
  const [tot] = await db
    .select({
      queries: sql<number>`coalesce(sum(${dnsResolverQueries.count}), 0)::int`,
      blocked: sql<number>`coalesce(sum(${dnsResolverQueries.count}) filter (where ${dnsResolverQueries.rcode} = 'BLOCKED'), 0)::int`,
      clients: sql<number>`count(distinct ${dnsResolverQueries.client})::int`,
    })
    .from(dnsResolverQueries)
    .where(where);
  const topBlocked = await db
    .select({
      registrable: dnsResolverQueries.registrable,
      count: sql<number>`sum(${dnsResolverQueries.count})::int`,
      clients: sql<number>`count(distinct ${dnsResolverQueries.client})::int`,
      by: sql<string>`max(${dnsResolverQueries.blockedBy})`,
    })
    .from(dnsResolverQueries)
    .where(and(where, eq(dnsResolverQueries.rcode, 'BLOCKED')))
    .groupBy(dnsResolverQueries.registrable)
    .orderBy(sql`2 desc`)
    .limit(10);
  const topClients = await db
    .select({
      client: dnsResolverQueries.client,
      agentId: sql<string | null>`max(${dnsResolverQueries.agentId})`,
      hostname: sql<string | null>`max(${agents.hostname})`,
      queries: sql<number>`sum(${dnsResolverQueries.count})::int`,
      blocked: sql<number>`coalesce(sum(${dnsResolverQueries.count}) filter (where ${dnsResolverQueries.rcode} = 'BLOCKED'), 0)::int`,
    })
    .from(dnsResolverQueries)
    .leftJoin(agents, eq(agents.id, dnsResolverQueries.agentId))
    .where(where)
    .groupBy(dnsResolverQueries.client)
    .orderBy(sql`4 desc`)
    .limit(10);
  return { hours, queries: tot?.queries ?? 0, blocked: tot?.blocked ?? 0, clients: tot?.clients ?? 0, topBlocked, topClients };
}

/** 最近被擋的查詢（設定頁「查詢紀錄」與一鍵放行）。 */
export async function recentBlocked(db: DB, limit = 50) {
  return db
    .select({
      ts: dnsResolverQueries.ts,
      client: dnsResolverQueries.client,
      hostname: agents.hostname,
      name: dnsResolverQueries.name,
      registrable: dnsResolverQueries.registrable,
      blockedBy: dnsResolverQueries.blockedBy,
      count: dnsResolverQueries.count,
    })
    .from(dnsResolverQueries)
    .leftJoin(agents, eq(agents.id, dnsResolverQueries.agentId))
    .where(eq(dnsResolverQueries.rcode, 'BLOCKED'))
    .orderBy(desc(dnsResolverQueries.ts))
    .limit(limit);
}

/** 設定頁要的全部資料（管理員 API 與頁面共用）。 */
export async function protectView(db: DB) {
  const s = await getProtect(db);
  const [servers, stats, blocked] = await Promise.all([listServers(db), resolverStats(db), recentBlocked(db)]);
  return {
    settings: s,
    servers,
    stats,
    recentBlocked: blocked.map((b) => ({ ...b, ts: b.ts.toISOString() })),
    feeds: domainFeedOptions(s.min_confidence),
    defaultUpstreams: DEFAULT_UPSTREAMS,
    composeTokenConfigured: !!env().dnsServerToken,
  };
}
export type ProtectView = Awaited<ReturnType<typeof protectView>>;
