// 測試用資料庫：記憶體內 PGlite，跑跟 PostgreSQL 一模一樣的 drizzle migration。
import path from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import { migrate } from 'drizzle-orm/pglite/migrator';
import * as schema from '@/drizzle/schema';
import { __setDbForTests, type DB } from '@/lib/db';

export async function createTestDb(): Promise<DB> {
  const client = new PGlite();
  const db = drizzle({ client, schema });
  await migrate(db, { migrationsFolder: path.resolve(__dirname, '../../drizzle') });
  const typed = db as unknown as DB;
  __setDbForTests(typed);
  return typed;
}
