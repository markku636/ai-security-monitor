// 通知：每分鐘找出規則建立之後發生的新事件 → 每條規則一次合併成一則訊息 → 排進佇列 → 送到各頻道（失敗重試 3 次）。
// 不在收資料的路徑裡插程式：用資料表裡的時間比對，Hub 重啟或暫時當掉也不會漏（只要還在時間範圍內）。
import { and, asc, count, desc, eq, gt, gte, inArray, isNull, lt, lte, sql, type SQL } from 'drizzle-orm';
import {
  actions,
  agents,
  destinations,
  findings,
  notificationChannels,
  notificationLog,
  notificationRules,
  notificationSeen,
  reports,
  settings,
} from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { makeT, type Lang, type TFn } from '@/lib/i18n/core';
import { CHANNEL_KINDS, decryptConfig, sendTo, type ChannelKind, type NotifyMessage, type SendDeps } from './channels';
import { secretKey } from './secret';

export const EVENTS = ['finding', 'dangerous_connection', 'host_offline', 'host_joined', 'action_pending', 'daily_digest'] as const;
export type NotifyEvent = (typeof EVENTS)[number];
export const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const;

const SETTINGS_KEY = 'notify.settings';
const MAX_LINES = 20;
const MAX_ATTEMPTS = 3;
const LOOKBACK_MS = 24 * 3600_000;

export interface NotifySettings {
  lang: Lang;
  /** 訊息裡的連結用（例 https://hub.example.com）。 */
  hubUrl: string | null;
}

export async function getNotifySettings(db: DB): Promise<NotifySettings> {
  const [row] = await db.select().from(settings).where(eq(settings.key, SETTINGS_KEY)).limit(1);
  const v = (row?.value ?? {}) as Partial<NotifySettings>;
  return { lang: v.lang === 'en' ? 'en' : 'zh-TW', hubUrl: typeof v.hubUrl === 'string' && v.hubUrl ? v.hubUrl.replace(/\/+$/, '') : null };
}

export async function saveNotifySettings(db: DB, s: NotifySettings, actor: string): Promise<void> {
  await db
    .insert(settings)
    .values({ key: SETTINGS_KEY, value: s, updatedBy: actor })
    .onConflictDoUpdate({ target: settings.key, set: { value: s, updatedAt: new Date(), updatedBy: actor } });
}

type Rule = typeof notificationRules.$inferSelect;

interface Item {
  key: string;
  line: string;
  severity?: string;
}

function sevAtLeast(min: string | null): string[] {
  const i = Math.max(0, SEVERITY_ORDER.indexOf((min ?? 'high') as (typeof SEVERITY_ORDER)[number]));
  return SEVERITY_ORDER.slice(i) as unknown as string[];
}

export function sevText(t: TFn, s: string): string {
  return ({ critical: t('嚴重'), high: t('高'), medium: t('中'), low: t('低'), info: t('資訊') } as Record<string, string>)[s] ?? s;
}

function minutesOf(rule: Rule, def: number): number {
  const m = Number(rule.params?.minutes);
  return Number.isFinite(m) && m >= 5 && m <= 7 * 24 * 60 ? Math.floor(m) : def;
}

/** 規則的新事件（還沒通知過的會在呼叫端過濾）。 */
async function detect(db: DB, rule: Rule, now: Date, t: TFn): Promise<Item[]> {
  const since = new Date(Math.max(rule.createdAt.getTime(), now.getTime() - LOOKBACK_MS));
  const agentCond = (col: typeof agents.id | typeof findings.agentId): SQL[] => (rule.agentId ? [eq(col, rule.agentId)] : []);
  switch (rule.event as NotifyEvent) {
    case 'finding': {
      const rows = await db
        .select({ agentId: findings.agentId, findingId: findings.findingId, hostname: agents.hostname, severity: findings.severity, title: findings.title })
        .from(findings)
        .innerJoin(agents, eq(agents.id, findings.agentId))
        .innerJoin(reports, eq(reports.id, findings.firstReportId))
        .where(
          and(
            isNull(agents.deletedAt),
            eq(findings.status, 'open'),
            inArray(findings.severity, sevAtLeast(rule.minSeverity)),
            gt(reports.receivedAt, since),
            ...agentCond(findings.agentId),
          ),
        )
        .orderBy(desc(reports.receivedAt))
        .limit(200);
      return rows.map((r) => ({ key: `f:${r.agentId}:${r.findingId}`, line: `[${sevText(t, r.severity)}] ${r.hostname} — ${r.title}`, severity: r.severity }));
    }
    case 'dangerous_connection': {
      const rows = await db
        .select({ agentId: destinations.agentId, hostname: agents.hostname, ip: destinations.remoteIp, port: destinations.remotePort, direction: destinations.direction, process: destinations.processName })
        .from(destinations)
        .innerJoin(agents, eq(agents.id, destinations.agentId))
        .where(and(isNull(agents.deletedAt), eq(destinations.worstVerdict, 'dangerous'), gt(destinations.lastRiskyAt, since), ...(rule.agentId ? [eq(destinations.agentId, rule.agentId)] : [])))
        .orderBy(desc(destinations.lastRiskyAt))
        .limit(200);
      return rows.map((r) => ({
        key: `d:${r.agentId}:${r.ip}:${r.port}:${r.direction}`,
        line:
          r.direction === 'inbound'
            ? t('{host} ← {ip}（連進 port {port}）', { host: r.hostname, ip: r.ip, port: r.port })
            : t('{host} → {ip}:{port}（{process}）', { host: r.hostname, ip: r.ip, port: r.port, process: r.process ?? '?' }),
        severity: 'high',
      }));
    }
    case 'host_offline': {
      const minutes = minutesOf(rule, 30);
      const cutoff = new Date(now.getTime() - minutes * 60_000);
      // 規則建立之後才斷線、而且是最近 7 天內斷線的
      const rows = await db
        .select({ id: agents.id, hostname: agents.hostname, lastSeenAt: agents.lastSeenAt })
        .from(agents)
        .where(
          and(
            isNull(agents.deletedAt),
            lt(agents.lastSeenAt, cutoff),
            gt(agents.lastSeenAt, new Date(rule.createdAt.getTime() - minutes * 60_000)),
            // 斷線超過 7 天的不再通知（已通知清單只保留 60 天，避免老早就關掉的主機一再出現）
            gt(agents.lastSeenAt, new Date(now.getTime() - 7 * 86_400_000)),
            ...agentCond(agents.id),
          ),
        )
        .limit(200);
      return rows.map((r) => ({
        key: `o:${r.id}:${Math.floor(r.lastSeenAt.getTime() / 1000)}`,
        line: t('{host} 已經 {m} 分鐘沒有回報（最後 {at} UTC）', {
          host: r.hostname,
          m: Math.floor((now.getTime() - r.lastSeenAt.getTime()) / 60_000),
          at: r.lastSeenAt.toISOString().slice(0, 16).replace('T', ' '),
        }),
        severity: 'medium',
      }));
    }
    case 'host_joined': {
      const rows = await db
        .select({ id: agents.id, hostname: agents.hostname, os: agents.osName })
        .from(agents)
        .where(and(isNull(agents.deletedAt), gt(agents.firstSeenAt, since)))
        .limit(200);
      return rows.map((r) => ({ key: `j:${r.id}`, line: `${r.hostname}${r.os ? `（${r.os}）` : ''}`, severity: 'info' }));
    }
    case 'action_pending': {
      const rows = await db
        .select({ id: actions.id, hostname: agents.hostname, kind: actions.kind, params: actions.params, reason: actions.reason })
        .from(actions)
        .innerJoin(agents, eq(agents.id, actions.agentId))
        .where(and(eq(actions.status, 'pending'), gt(actions.createdAt, since), ...(rule.agentId ? [eq(actions.agentId, rule.agentId)] : [])))
        .limit(200);
      return rows.map((r) => {
        const target = String(r.params?.ip ?? r.params?.port ?? '');
        return { key: `a:${r.id}`, line: `${r.hostname}：${r.kind} ${target}${r.reason ? ` — ${r.reason}` : ''}`.trim(), severity: 'medium' };
      });
    }
    case 'daily_digest': {
      const hour = Number.isInteger(rule.params?.hour) ? Number(rule.params.hour) : 9;
      // 以 UTC 計：Hub 的容器通常是 UTC，網頁上會註明
      if (now.getUTCHours() !== hour) return [];
      const day = now.toISOString().slice(0, 10);
      const [open, fresh, offline, pending] = await Promise.all([
        db
          .select({ severity: findings.severity, n: count() })
          .from(findings)
          .innerJoin(agents, eq(agents.id, findings.agentId))
          .where(and(isNull(agents.deletedAt), inArray(findings.status, ['open', 'acked'])))
          .groupBy(findings.severity),
        db
          .select({ n: count() })
          .from(findings)
          .innerJoin(reports, eq(reports.id, findings.firstReportId))
          .where(gt(reports.receivedAt, new Date(now.getTime() - LOOKBACK_MS))),
        db
          .select({ n: count() })
          .from(agents)
          .where(and(isNull(agents.deletedAt), lt(agents.lastSeenAt, new Date(now.getTime() - 60 * 60_000)))),
        db.select({ n: count() }).from(actions).where(eq(actions.status, 'pending')),
      ]);
      const by = Object.fromEntries(open.map((r) => [r.severity, Number(r.n)])) as Record<string, number>;
      return [
        {
          key: `digest:${day}`,
          line: [
            t('待處理問題：嚴重 {c}、高 {h}、中 {m}、低 {l}', { c: by.critical ?? 0, h: by.high ?? 0, m: by.medium ?? 0, l: by.low ?? 0 }),
            t('最近 24 小時新增 {n} 個問題', { n: Number(fresh[0]?.n ?? 0) }),
            t('超過 1 小時沒回報的主機：{n} 台', { n: Number(offline[0]?.n ?? 0) }),
            t('等待審核的封鎖：{n} 個', { n: Number(pending[0]?.n ?? 0) }),
          ].join('\n'),
          severity: (by.critical ?? 0) > 0 ? 'critical' : (by.high ?? 0) > 0 ? 'high' : 'info',
        },
      ];
    }
    default:
      return [];
  }
}

function titleOf(t: TFn, event: NotifyEvent, n: number): string {
  switch (event) {
    case 'finding':
      return t('ai-security-monitor：{n} 個新的問題', { n });
    case 'dangerous_connection':
      return t('ai-security-monitor：{n} 條新的危險連線', { n });
    case 'host_offline':
      return t('ai-security-monitor：{n} 台主機沒有回報', { n });
    case 'host_joined':
      return t('ai-security-monitor：{n} 台新主機加入', { n });
    case 'action_pending':
      return t('ai-security-monitor：{n} 個封鎖等待審核', { n });
    case 'daily_digest':
      return t('ai-security-monitor 每日摘要');
  }
}

function linkOf(hub: string | null, event: NotifyEvent, rule: Rule): string | null {
  if (!hub) return null;
  const path: Record<NotifyEvent, string> = {
    finding: rule.agentId ? `/agents/${encodeURIComponent(rule.agentId)}?tab=findings` : '/findings',
    dangerous_connection: '/connections?verdict=dangerous',
    host_offline: '/agents',
    host_joined: '/agents',
    action_pending: '/actions',
    daily_digest: '/',
  };
  return hub + path[event];
}

const worst = (items: Item[]) => SEVERITY_ORDER[Math.max(...items.map((i) => SEVERITY_ORDER.indexOf((i.severity ?? 'info') as (typeof SEVERITY_ORDER)[number])))] ?? 'info';

export function buildMessage(t: TFn, rule: Rule, items: Item[], hub: string | null): NotifyMessage {
  const event = rule.event as NotifyEvent;
  const lines = items.slice(0, MAX_LINES).flatMap((i) => i.line.split('\n'));
  if (items.length > MAX_LINES) lines.push(t('…還有 {n} 個', { n: items.length - MAX_LINES }));
  return { event, title: titleOf(t, event, items.length), lines, link: linkOf(hub, event, rule), severity: worst(items) };
}

export interface RunResult {
  queued: number;
  sent: number;
  failed: number;
}

/** 偵測＋送出一輪（排程每分鐘呼叫）。多個 Hub 行程用 advisory lock，只有一個在做。 */
export async function runNotifications(db: DB, now = new Date(), deps: SendDeps = {}): Promise<RunResult> {
  return db.transaction(async (tx) => {
    const t = tx as unknown as DB;
    const lock = await t.execute(sql`select pg_try_advisory_xact_lock(hashtext('asa_hub.notify')) as ok`);
    const ok = (lock as unknown as { rows?: { ok: boolean }[] }).rows?.[0]?.ok ?? true;
    if (!ok) return { queued: 0, sent: 0, failed: 0 };
    const s = await getNotifySettings(t);
    const tr = makeT(s.lang);
    const rules = await t.select().from(notificationRules).where(eq(notificationRules.enabled, true));
    const channels = await t.select().from(notificationChannels).where(eq(notificationChannels.enabled, true));
    const live = new Set(channels.map((c) => c.id));
    let queued = 0;
    for (const rule of rules) {
      const targets = rule.channelIds.filter((id) => live.has(id));
      if (!targets.length) continue;
      const items = await detect(t, rule, now, tr);
      if (!items.length) continue;
      const seen = await t
        .select({ key: notificationSeen.key })
        .from(notificationSeen)
        .where(and(eq(notificationSeen.ruleId, rule.id), inArray(notificationSeen.key, items.map((i) => i.key))));
      const done = new Set(seen.map((r) => r.key));
      const fresh = items.filter((i) => !done.has(i.key));
      if (!fresh.length) continue;
      await t.insert(notificationSeen).values(fresh.map((i) => ({ ruleId: rule.id, key: i.key, at: now }))).onConflictDoNothing();
      const m = buildMessage(tr, rule, fresh, s.hubUrl);
      await t.insert(notificationLog).values(
        targets.map((channelId) => ({ ruleId: rule.id, channelId, event: m.event, title: m.title, body: JSON.stringify({ lines: m.lines, severity: m.severity }), link: m.link ?? null, createdAt: now })),
      );
      queued += targets.length;
    }
    const { sent, failed } = await deliver(t, channels, tr, deps, now);
    // 紀錄保留 30 天、已通知清單 60 天
    await t.delete(notificationLog).where(lt(notificationLog.createdAt, new Date(now.getTime() - 30 * 86_400_000)));
    await t.delete(notificationSeen).where(lt(notificationSeen.at, new Date(now.getTime() - 60 * 86_400_000)));
    return { queued, sent, failed };
  });
}

type Channel = typeof notificationChannels.$inferSelect;

async function deliver(db: DB, channels: Channel[], t: TFn, deps: SendDeps, now: Date): Promise<{ sent: number; failed: number }> {
  const pending = await db
    .select()
    .from(notificationLog)
    .where(and(eq(notificationLog.status, 'pending'), lte(notificationLog.attempts, MAX_ATTEMPTS - 1), gte(notificationLog.createdAt, new Date(now.getTime() - LOOKBACK_MS))))
    .orderBy(asc(notificationLog.id))
    .limit(100);
  if (!pending.length) return { sent: 0, failed: 0 };
  const key = await secretKey(db);
  const byId = new Map(channels.map((c) => [c.id, c]));
  let sent = 0;
  let failed = 0;
  for (const row of pending) {
    const ch = byId.get(row.channelId);
    if (!ch) continue;
    const body = JSON.parse(row.body) as { lines: string[]; severity?: string };
    const m: NotifyMessage = { event: row.event, title: row.title, lines: body.lines, severity: body.severity, link: row.link };
    try {
      await sendTo(ch.kind as ChannelKind, decryptConfig(ch.kind as ChannelKind, ch.config, key), m, t('在 Security Hub 開啟'), deps);
      await db.update(notificationLog).set({ status: 'sent', attempts: row.attempts + 1, sentAt: new Date(), error: null }).where(eq(notificationLog.id, row.id));
      await db.update(notificationChannels).set({ lastOkAt: new Date() }).where(eq(notificationChannels.id, ch.id));
      sent++;
    } catch (e) {
      const msg = (e instanceof Error ? e.message : String(e)).slice(0, 300);
      const attempts = row.attempts + 1;
      await db
        .update(notificationLog)
        .set({ attempts, error: msg, status: attempts >= MAX_ATTEMPTS ? 'failed' : 'pending' })
        .where(eq(notificationLog.id, row.id));
      await db.update(notificationChannels).set({ lastError: msg, lastErrorAt: new Date() }).where(eq(notificationChannels.id, ch.id));
      if (attempts >= MAX_ATTEMPTS) failed++;
    }
  }
  return { sent, failed };
}

/** 「送測試訊息」：馬上送，不進佇列。 */
export async function sendTest(db: DB, channelId: string, deps: SendDeps = {}): Promise<{ ok: boolean; error?: string }> {
  const [ch] = await db.select().from(notificationChannels).where(eq(notificationChannels.id, channelId)).limit(1);
  if (!ch || !(CHANNEL_KINDS as readonly string[]).includes(ch.kind)) return { ok: false, error: 'not_found' };
  const s = await getNotifySettings(db);
  const t = makeT(s.lang);
  try {
    await sendTo(
      ch.kind as ChannelKind,
      decryptConfig(ch.kind as ChannelKind, ch.config, await secretKey(db)),
      { event: 'test', title: t('ai-security-monitor 測試通知'), lines: [t('收到這則訊息代表「{name}」設定正確。', { name: ch.name })], link: s.hubUrl, severity: 'info' },
      t('在 Security Hub 開啟'),
      deps,
    );
    await db.update(notificationChannels).set({ lastOkAt: new Date(), lastError: null }).where(eq(notificationChannels.id, ch.id));
    return { ok: true };
  } catch (e) {
    const error = (e instanceof Error ? e.message : String(e)).slice(0, 300);
    await db.update(notificationChannels).set({ lastError: error, lastErrorAt: new Date() }).where(eq(notificationChannels.id, ch.id));
    return { ok: false, error };
  }
}

// ---- 排程 ----

const g = globalThis as unknown as { __asaNotifyTimer?: ReturnType<typeof setInterval>; __asaNotifyRunning?: boolean };

async function runSafely(): Promise<void> {
  if (g.__asaNotifyRunning) return;
  g.__asaNotifyRunning = true;
  try {
    const { getDb } = await import('@/lib/db');
    const db = getDb();
    // 沒有任何啟用的規則就不開交易
    const [n] = await db.select({ n: count() }).from(notificationRules).where(eq(notificationRules.enabled, true));
    if (Number(n?.n ?? 0) > 0) await runNotifications(db);
    // 自動回應（全域開關關閉時只會解除到期的封鎖）
    const { runAutoResponse } = await import('@/lib/response/engine');
    await runAutoResponse(db);
  } catch (err) {
    console.warn('[ai-security-monitor-hub] notifications failed', err instanceof Error ? err.message : err);
  } finally {
    g.__asaNotifyRunning = false;
  }
}

/** Hub 啟動時呼叫：每分鐘一輪（通知＋自動回應）。 */
export function startNotifyScheduler(everyMs = 60_000): void {
  if (g.__asaNotifyTimer) return;
  g.__asaNotifyTimer = setInterval(() => void runSafely(), everyMs);
  g.__asaNotifyTimer.unref?.();
}
