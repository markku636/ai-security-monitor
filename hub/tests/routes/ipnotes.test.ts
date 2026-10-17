import { eq } from 'drizzle-orm';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GET, POST } from '@/app/api/v1/ip-notes/route';
import { auditLog, ipNotes } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { ipNoteMap } from '@/lib/queries/ipnotes';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const admin = { authorization: 'Bearer test-admin' };
const IP = '76.76.21.21';

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
});

beforeEach(async () => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  resetEnvForTests();
  resetRateLimitsForTests();
  await db.delete(ipNotes);
});

const post = (body: unknown, headers: Record<string, string> = admin) => POST(req('/api/v1/ip-notes', { method: 'POST', body, headers }));

describe('ip notes', () => {
  it('sets, reads, overwrites and deletes a note with audit entries', async () => {
    const r1 = await post({ ip: IP, note: '  Vercel 邊緣節點，公司官網用  ' });
    expect(r1.status).toBe(200);
    expect(((await r1.json()) as { note: { note: string } }).note.note).toBe('Vercel 邊緣節點，公司官網用');

    const g = (await (await GET(req(`/api/v1/ip-notes?ip=${IP}`, { headers: admin }))).json()) as { note: { note: string; updatedBy: string } };
    expect(g.note).toMatchObject({ note: 'Vercel 邊緣節點，公司官網用', updatedBy: 'admin:bearer' });

    expect((await post({ ip: IP, note: '已確認安全' })).status).toBe(200);
    expect((await ipNoteMap([IP, '1.1.1.1', null])).get(IP)).toBe('已確認安全');

    const del = (await (await post({ ip: IP, note: '   ' })).json()) as { note: unknown };
    expect(del.note).toBeNull();
    expect(await db.select().from(ipNotes)).toEqual([]);

    const actions = (await db.select().from(auditLog).where(eq(auditLog.targetId, IP))).map((a) => a.action);
    expect(actions).toEqual(['ip_note.set', 'ip_note.set', 'ip_note.delete']);
  });

  it('rejects bad input and non-admins', async () => {
    expect((await post({ ip: 'not-an-ip', note: 'x' })).status).toBe(400);
    expect((await post({ ip: IP, note: 'x'.repeat(2001) })).status).toBe(400);
    expect((await GET(req('/api/v1/ip-notes?ip=nope', { headers: admin }))).status).toBe(400);
    expect((await post({ ip: IP, note: 'x' }, {})).status).toBe(401);
    expect((await GET(req(`/api/v1/ip-notes?ip=${IP}`))).status).toBe(401);
    expect(await db.select().from(ipNotes)).toEqual([]);
  });
});
