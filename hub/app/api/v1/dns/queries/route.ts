// 防護 DNS 的查詢紀錄（每分鐘依用戶端、網域、類型、結果聚合；離線時 dns-server 暫存、恢復後補送，同一列重送以新值覆蓋）。
import { identify } from '@/lib/auth/access';
import { hit } from '@/lib/auth/ratelimit';
import { getDb } from '@/lib/db';
import { applyResolver, dnsServerOf, ResolverBatch } from '@/lib/dns/protect';
import { error, json } from '@/lib/http';
import { IngestRejected, readIngestBody } from '@/lib/ingest/guard';
import { zodRule } from '@/lib/ingest/schema';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  const db = getDb();
  const who = await dnsServerOf(await identify(req), req, db);
  if (!who) return error(401, 'unauthorized');
  if (hit(`dns-queries:${who.id}`, 60_000) > 60) return json({ error: 'too_frequent', retry_after_ms: 60_000 }, 429, { 'retry-after': '60' });
  let raw: unknown;
  try {
    raw = (await readIngestBody(req, 2 * 1024 * 1024)).value;
  } catch (e) {
    if (e instanceof IngestRejected) return error(e.status, e.status === 413 ? 'too_large' : 'bad_request', { rule: e.rule });
    throw e;
  }
  const p = ResolverBatch.safeParse(raw);
  if (!p.success) return error(400, 'bad_request', { rule: zodRule(p.error) });
  const r = await applyResolver(db, who, p.data);
  return json({ ok: true, ...r, server_time: new Date().toISOString() });
}
