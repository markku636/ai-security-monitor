// 清除歷史：AI 分析（執行中保留、AI 程式對話紀錄）、連線歷史（可限主機／天數）、外部情資快取；權限、稽核、保留期限。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { DELETE as deleteOne } from '@/app/api/ai/analyses/[id]/route';
import { DELETE as historyDelete, GET as historyGet } from '@/app/api/v1/admin/history/route';
import { agents, aiAnalyses, auditLog, destinations, ipReputation } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { pruneHistory } from '@/lib/history';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const admin = { authorization: 'Bearer test-admin' };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asa-history-'));
const DAY = 86_400_000;
const ago = (d: number) => new Date(Date.now() - d * DAY);
let db: DB;

async function seed() {
  await db.delete(aiAnalyses);
  await db.delete(destinations);
  await db.delete(ipReputation);
  await db
    .insert(agents)
    .values([
      { id: 'h-a', hostname: 'host-a' },
      { id: 'h-b', hostname: 'host-b' },
    ])
    .onConflictDoNothing();
  await db.insert(aiAnalyses).values([
    { id: 'ai_0000000000000001', provider: 'claude', scope: 'fleet', prompt: 'old', createdBy: 'admin', status: 'done', createdAt: ago(100) },
    { id: 'ai_0000000000000002', provider: 'claude', scope: 'fleet', prompt: 'new', createdBy: 'admin', status: 'done', createdAt: ago(1) },
    { id: 'ai_0000000000000003', provider: 'codex', scope: 'fleet', prompt: 'busy', createdBy: 'admin', status: 'running', createdAt: ago(200) },
  ]);
  const dest = (agentId: string, ip: string, lastDays: number) => ({
    agentId,
    remoteIp: ip,
    remotePort: 443,
    direction: 'outbound',
    firstSeenAt: ago(lastDays + 1),
    lastSeenAt: ago(lastDays),
    worstVerdict: 'suspicious',
    lastRiskyAt: ago(lastDays),
  });
  await db.insert(destinations).values([dest('h-a', '203.0.113.1', 60), dest('h-a', '203.0.113.2', 1), dest('h-b', '203.0.113.3', 1)]);
  await db.insert(ipReputation).values([
    { ip: '203.0.113.1', results: {}, queriedAt: ago(40) },
    { ip: '203.0.113.2', results: {}, queriedAt: ago(2) },
  ]);
}

const del = (q: string, headers: Record<string, string> = admin) => historyDelete(req(`/api/v1/admin/history?${q}`, { method: 'DELETE', headers }));

beforeAll(async () => {
  db = await createTestDb();
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

beforeEach(async () => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  delete process.env.ASA_HUB_AI_RETENTION_DAYS;
  delete process.env.ASA_HUB_IPINTEL_CACHE_DAYS;
  resetEnvForTests();
  await seed();
});

describe('history cleanup', () => {
  it('reports counts and requires admin', async () => {
    expect((await historyGet(req('/api/v1/admin/history'))).status).toBe(401);
    const s = (await (await historyGet(req('/api/v1/admin/history', { headers: admin }))).json()).stats;
    expect(s.ai).toMatchObject({ count: 3, retentionDays: 90 });
    expect(s.connections).toMatchObject({ count: 3, retentionDays: null });
    expect(s.ipintel).toMatchObject({ count: 2, retentionDays: 30 });
    expect((await del('kind=bogus')).status).toBe(400);
    expect((await del('kind=ai', {})).status).toBe(401);
  });

  it('clears AI analyses but keeps running ones, by age, one at a time, and the CLI transcripts', async () => {
    let r = await (await del('kind=ai&older_than_days=30')).json();
    expect(r.deleted).toBe(1);
    expect((await db.select().from(aiAnalyses)).map((x) => x.id).sort()).toEqual(['ai_0000000000000002', 'ai_0000000000000003']);
    const one = await deleteOne(req('/api/ai/analyses/ai_0000000000000002', { method: 'DELETE', headers: admin }), { params: Promise.resolve({ id: 'ai_0000000000000002' }) });
    expect(one.status).toBe(200);
    const running = await deleteOne(req('/api/ai/analyses/ai_0000000000000003', { method: 'DELETE', headers: admin }), { params: Promise.resolve({ id: 'ai_0000000000000003' }) });
    expect(running.status).toBe(404);

    const claude = path.join(tmp, 'claude');
    const codex = path.join(tmp, 'codex');
    fs.mkdirSync(path.join(claude, 'projects', '-tmp-asa-hub-ai-abc123'), { recursive: true });
    fs.mkdirSync(path.join(claude, 'projects', '-home-user-myproject'), { recursive: true });
    fs.writeFileSync(path.join(claude, '.credentials.json'), '{}');
    fs.mkdirSync(path.join(codex, 'sessions', '2026'), { recursive: true });
    fs.writeFileSync(path.join(codex, 'auth.json'), '{}');
    process.env.CLAUDE_CONFIG_DIR = claude;
    process.env.CODEX_HOME = codex;
    try {
      r = await (await del('kind=ai&cli=1')).json();
      expect(r.cli).toMatchObject({ claude: 1, codex: 1, skipped: [] });
      expect(fs.readdirSync(path.join(claude, 'projects'))).toEqual(['-home-user-myproject']);
      expect(fs.existsSync(path.join(claude, '.credentials.json'))).toBe(true);
      expect(fs.existsSync(path.join(codex, 'auth.json'))).toBe(true);
    } finally {
      delete process.env.CLAUDE_CONFIG_DIR;
      delete process.env.CODEX_HOME;
    }
    const [a] = (await db.select().from(auditLog).where(eq(auditLog.action, 'history.cleared'))).slice(-1);
    expect(a).toMatchObject({ targetId: 'ai' });
  });

  it('clears connection history for one host or by age, and the external intel cache', async () => {
    let r = await (await del('kind=connections&agent_id=h-b')).json();
    expect(r.deleted).toBe(1);
    r = await (await del('kind=connections&older_than_days=30')).json();
    expect(r.deleted).toBe(1);
    expect((await db.select().from(destinations)).map((d) => d.remoteIp)).toEqual(['203.0.113.2']);
    r = await (await del('kind=ipintel')).json();
    expect(r).toMatchObject({ deleted: 2 });
    expect(r.stats.ipintel.count).toBe(0);
  });

  it('prunes by retention days (0 keeps everything)', async () => {
    expect(await pruneHistory(db)).toEqual({ ai: 1, ipintel: 1, domains: 0 });
    await seed();
    process.env.ASA_HUB_AI_RETENTION_DAYS = '0';
    process.env.ASA_HUB_IPINTEL_CACHE_DAYS = '0';
    resetEnvForTests();
    expect(await pruneHistory(db)).toEqual({ ai: 0, ipintel: 0, domains: 0 });
  });
});
