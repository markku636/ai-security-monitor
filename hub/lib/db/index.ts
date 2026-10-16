// 資料庫：PostgreSQL（node-postgres pool）。測試以 __setDbForTests 換成 PGlite。
import path from 'node:path';
import pg from 'pg';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core';
import * as schema from '@/drizzle/schema';
import { env } from '@/lib/env';

export type DB = PgDatabase<PgQueryResultHKT, typeof schema>;

const g = globalThis as unknown as {
  __asaDb?: DB;
  __asaPool?: pg.Pool;
  __asaMigrated?: Promise<void> | true;
};

export class DbNotConfigured extends Error {
  constructor() {
    super('ASA_HUB_DATABASE_URL is not set');
  }
}

export function migrationsFolder(): string {
  return process.env.ASA_HUB_MIGRATIONS_DIR || path.join(process.cwd(), 'drizzle');
}

export function getDb(): DB {
  if (g.__asaDb) return g.__asaDb;
  const url = env().databaseUrl;
  if (!url) throw new DbNotConfigured();
  const pool = new pg.Pool({ connectionString: url, max: 4, idleTimeoutMillis: 30_000 });
  g.__asaPool = pool;
  g.__asaDb = drizzle({ client: pool, schema }) as unknown as DB;
  return g.__asaDb;
}

export function __setDbForTests(db: DB): void {
  g.__asaDb = db;
  g.__asaMigrated = true;
}

/** 啟動時跑 migration；以 advisory lock 防止兩個 hub 同時跑。 */
export async function ensureMigrated(): Promise<void> {
  if (g.__asaMigrated === true) return;
  if (g.__asaMigrated) return g.__asaMigrated;
  g.__asaMigrated = (async () => {
    getDb();
    const pool = g.__asaPool!;
    const client = await pool.connect();
    try {
      await client.query("select pg_advisory_lock(hashtext('asa_hub.migrate'))");
      try {
        await migrate(drizzle({ client, schema }), { migrationsFolder: migrationsFolder() });
      } finally {
        await client.query("select pg_advisory_unlock(hashtext('asa_hub.migrate'))");
      }
    } finally {
      client.release();
    }
    g.__asaMigrated = true;
  })();
  try {
    await g.__asaMigrated;
  } catch (e) {
    g.__asaMigrated = undefined;
    throw e;
  }
}

export interface DbHealth {
  status: 'ok' | 'error' | 'not_configured';
  latencyMs?: number;
  error?: string;
}

export async function pingDb(): Promise<DbHealth> {
  let db: DB;
  try {
    db = getDb();
  } catch (e) {
    if (e instanceof DbNotConfigured) return { status: 'not_configured' };
    return { status: 'error', error: String(e) };
  }
  const started = Date.now();
  try {
    await ensureMigrated();
    await db.execute(sql`select 1`);
    return { status: 'ok', latencyMs: Date.now() - started };
  } catch (e) {
    return { status: 'error', error: e instanceof Error ? e.message : String(e) };
  }
}
