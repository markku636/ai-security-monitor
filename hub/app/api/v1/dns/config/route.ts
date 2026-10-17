// 防護 DNS 伺服器拉設定（封鎖開關、暫停、上游、清單、自訂封鎖／允許）；帶 If-None-Match 沒變就 304。
import { identify } from '@/lib/auth/access';
import { getDb } from '@/lib/db';
import { dnsServerOf, getProtect, serverConfig } from '@/lib/dns/protect';
import { error, json } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const db = getDb();
  const who = await dnsServerOf(await identify(req), req, db);
  if (!who) return error(401, 'unauthorized');
  const cfg = serverConfig(await getProtect(db));
  if (req.headers.get('if-none-match') === cfg.etag) return new Response(null, { status: 304, headers: { etag: cfg.etag } });
  return json({ ...cfg, server_id: who.id }, 200, { etag: cfg.etag });
}
