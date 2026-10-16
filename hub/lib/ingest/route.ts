// agent 端點共用流程：client 金鑰 → 讀 body（gzip / 上限 / 結構檢查）→ zod → 依 agent 限流 → 寫入。
import type { z } from 'zod';
import { audit } from '@/lib/audit';
import { identify, type Identity } from '@/lib/auth/access';
import { getDb, type DB } from '@/lib/db';
import { error, json, sourceIp } from '@/lib/http';
import { IngestRejected, readIngestBody } from './guard';
import { zodRule } from './schema';

const g = globalThis as unknown as { __asaIngestLast?: Map<string, number> };

/** 同一 agent、同一類上傳的最短間隔；回傳還要等幾毫秒（0＝可接受並記錄）。 */
export function throttle(key: string, minMs: number): number {
  if (minMs <= 0) return 0;
  if (!g.__asaIngestLast) g.__asaIngestLast = new Map();
  const last = g.__asaIngestLast.get(key) ?? 0;
  const wait = last + minMs - Date.now();
  if (wait > 0) return wait;
  g.__asaIngestLast.set(key, Date.now());
  return 0;
}

export function resetThrottleForTests(): void {
  g.__asaIngestLast = new Map();
}

export interface IngestCtx<T> {
  body: T;
  id: Identity;
  db: DB;
  ip: string;
  bytes: number;
}

export async function handleIngest<S extends z.ZodTypeAny>(
  req: Request,
  schema: S,
  opts: { kind: string; agentIdOf: (b: z.infer<S>) => string; minIntervalMs: number; maxBytes?: number },
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
      await audit({ actor: `client:${id.keyIndex ?? 'admin'}`, actorRole: id.role, action: `ingest.${opts.kind}.rejected`, sourceIp: ip, details: { rule: e.rule } });
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
  const wait = throttle(`${opts.kind}:${agentId}`, opts.minIntervalMs);
  if (wait > 0) {
    return json({ error: 'too_frequent', retry_after_ms: wait }, 429, { 'retry-after': String(Math.ceil(wait / 1000)) });
  }
  try {
    return await fn({ body, id, db: getDb(), ip, bytes });
  } catch (e) {
    if (e instanceof IngestRejected) return error(e.status, e.rule);
    throw e;
  }
}
