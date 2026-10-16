// agent 端點共用流程：client 金鑰 → 讀 body（gzip / 上限 / 結構檢查）→ zod → 依 agent 限流 → 寫入。
import type { z } from 'zod';
import { audit } from '@/lib/audit';
import { clientLabel, identify, type Identity } from '@/lib/auth/access';
import { hit } from '@/lib/auth/ratelimit';
import { getDb, type DB } from '@/lib/db';
import { error, json, sourceIp } from '@/lib/http';
import { IngestRejected, readIngestBody } from './guard';
import { agentTokenOf, pinAgentToken, type PinResult } from './identity';
import { zodRule } from './schema';

const g = globalThis as unknown as { __asaIngestLast?: Map<string, number> };

/**
 * 同一 agent、同一類上傳的最短間隔；回傳還要等幾毫秒（0＝可接受並記錄）。
 * `at` 是內容本身的時間（報告完成時間）：用它比較間隔，agent 斷線期間暫存的報告恢復後一次補送
 * 也不會被擋（彼此仍相隔一個掃描週期）；真正重複狂送（時間幾乎相同）才擋。沒給 `at` 就用收到時間。
 */
export function throttle(key: string, minMs: number, at?: number): number {
  if (minMs <= 0) return 0;
  if (!g.__asaIngestLast) g.__asaIngestLast = new Map();
  const t = at ?? Date.now();
  const last = g.__asaIngestLast.get(key);
  if (last !== undefined && Math.abs(t - last) < minMs) {
    return at === undefined ? last + minMs - t : minMs - Math.abs(t - last);
  }
  g.__asaIngestLast.set(key, t);
  return 0;
}

/** 不論內容時間，每 agent 每分鐘的硬上限（防偽造時間戳灌資料）。 */
export const BURST_PER_MINUTE = 30;

export function resetThrottleForTests(): void {
  g.__asaIngestLast = new Map();
}

export interface IngestCtx<T> {
  body: T;
  id: Identity;
  db: DB;
  ip: string;
  bytes: number;
  agentToken: string | null;
  pin: PinResult;
}

export async function handleIngest<S extends z.ZodTypeAny>(
  req: Request,
  schema: S,
  opts: {
    kind: string;
    agentIdOf: (b: z.infer<S>) => string;
    minIntervalMs: number;
    maxBytes?: number;
    /** 內容時間（毫秒）；給了就依內容時間比較間隔（見 throttle）。 */
    contentTimeOf?: (b: z.infer<S>) => number;
    /** 限流前的捷徑（例如已收過的報告直接回 duplicate，重送不該被 429 卡住）。 */
    precheck?: (b: z.infer<S>, db: DB) => Promise<Response | null>;
  },
  fn: (ctx: IngestCtx<z.infer<S>>) => Promise<Response>,
): Promise<Response> {
  const id = await identify(req);
  if (id.role !== 'client' && !(id.role === 'admin' && id.via === 'bearer')) {
    return error(401, 'unauthorized');
  }
  const ip = sourceIp(req);
  let raw: unknown;
  let bytes = 0;
  try {
    const r = await readIngestBody(req, opts.maxBytes);
    raw = r.value;
    bytes = r.bytes;
  } catch (e) {
    if (e instanceof IngestRejected) {
      await audit({ actor: clientLabel(id), actorRole: id.role, action: `ingest.${opts.kind}.rejected`, sourceIp: ip, details: { rule: e.rule } });
      return error(e.status, e.status === 413 ? 'too_large' : 'bad_request', { rule: e.rule });
    }
    throw e;
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    return error(400, 'bad_request', { rule: zodRule(parsed.error) });
  }
  const body = parsed.data as z.infer<S>;
  const agentId = opts.agentIdOf(body);
  const header = req.headers.get('x-asa-agent-id');
  if (header && header !== agentId) return error(400, 'bad_request', { rule: 'agent_id_mismatch' });
  const agentToken = agentTokenOf(req);
  const pin = await pinAgentToken(getDb(), agentId, agentToken);
  if (pin === 'mismatch') {
    await audit({ actor: clientLabel(id), actorRole: id.role, action: `ingest.${opts.kind}.token_mismatch`, targetType: 'agent', targetId: agentId, sourceIp: ip });
    return error(403, 'agent_token_mismatch');
  }
  if (opts.precheck) {
    const early = await opts.precheck(body, getDb());
    if (early) return early;
  }
  if (hit(`burst:${opts.kind}:${agentId}`, 60_000) > BURST_PER_MINUTE) {
    return json({ error: 'too_frequent', retry_after_ms: 60_000 }, 429, { 'retry-after': '60' });
  }
  const wait = throttle(`${opts.kind}:${agentId}`, opts.minIntervalMs, opts.contentTimeOf?.(body));
  if (wait > 0) {
    return json({ error: 'too_frequent', retry_after_ms: wait }, 429, { 'retry-after': String(Math.ceil(wait / 1000)) });
  }
  try {
    return await fn({ body, id, db: getDb(), ip, bytes, agentToken, pin });
  } catch (e) {
    if (e instanceof IngestRejected) return error(e.status, e.rule);
    throw e;
  }
}
