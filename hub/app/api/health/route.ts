// 健康檢查（不需金鑰）：Docker HEALTHCHECK 與 agent 連線測試用。資料庫不通回 503。
import { pingDb } from '@/lib/db';
import { env, isOpenMode } from '@/lib/env';
import { json } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<Response> {
  const db = await pingDb();
  const e = env();
  const ok = db.status === 'ok';
  return json(
    {
      ok,
      version: e.version,
      edition: e.edition,
      open_mode: isOpenMode(),
      db: db.status,
      ...(db.latencyMs !== undefined ? { db_latency_ms: db.latencyMs } : {}),
      time: new Date().toISOString(),
    },
    ok ? 200 : 503,
  );
}
