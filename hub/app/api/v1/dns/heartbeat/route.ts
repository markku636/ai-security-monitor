// 防護 DNS 伺服器每 30 秒的心跳（查詢量、快取、封鎖、延遲、上游、清單）；回應帶設定的 etag，變了 dns-server 就馬上重拉。
import { identify } from '@/lib/auth/access';
import { hit } from '@/lib/auth/ratelimit';
import { getDb } from '@/lib/db';
import { dnsServerOf, getProtect, recordHeartbeat, serverConfig, ServerHeartbeat } from '@/lib/dns/protect';
import { BodyTooLarge, error, json, readJson, sourceIp } from '@/lib/http';
import { zodRule } from '@/lib/ingest/schema';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  const db = getDb();
  const who = await dnsServerOf(await identify(req), req, db);
  if (!who) return error(401, 'unauthorized');
  if (hit(`dns-heartbeat:${who.id}`, 60_000) > 20) return json({ error: 'too_frequent', retry_after_ms: 60_000 }, 429, { 'retry-after': '60' });
  let raw: unknown;
  try {
    raw = await readJson(req, 64 * 1024);
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, 'bad_request');
  }
  const p = ServerHeartbeat.safeParse(raw);
  if (!p.success) return error(400, 'bad_request', { rule: zodRule(p.error) });
  try {
    await recordHeartbeat(db, who, p.data, sourceIp(req));
  } catch {
    return error(413, 'too_large');
  }
  const cfg = serverConfig(await getProtect(db));
  return json({ ok: true, server_id: who.id, config_etag: cfg.etag, blocking: cfg.blocking, server_time: new Date().toISOString() });
}
