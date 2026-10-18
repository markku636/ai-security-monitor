import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { POST as ingestReport } from '@/app/api/v1/ingest/report/route';
import { GET as reportGet } from '@/app/api/v1/report/route';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { makeT } from '@/lib/i18n/core';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { buildReport, parsePeriod, sevTotal } from '@/lib/report/build';
import { highlights, toMarkdown } from '@/lib/report/text';
import { createTestDb } from '../helpers/db';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const A = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';

function post(url: string, body: unknown, token = 'client-a') {
  return new Request(`http://localhost:3000${url}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
  resetEnvForTests();
  resetThrottleForTests();
  expect((await register(post('/api/v1/agents/register', load('register.v1.json')))).status).toBe(200);
  // 契約範例報告：2026-10-16 兩個嚴重問題（intel、ports）
  expect((await ingestReport(post('/api/v1/ingest/report', load('report.v1.json')))).status).toBe(200);
});

describe('security report', () => {
  it('parses periods (inclusive end, max length)', () => {
    const p = parsePeriod('2026-10-10', '2026-10-16')!;
    expect(p.from.toISOString()).toBe('2026-10-10T00:00:00.000Z');
    expect(p.to.toISOString()).toBe('2026-10-17T00:00:00.000Z');
    expect(parsePeriod('2026-10-17', '2026-10-16')).toBeNull();
    expect(parsePeriod('2025-01-01', '2026-10-16')).toBeNull();
    expect(parsePeriod('bad', '2026-10-16')).toBeNull();
    expect(parsePeriod(undefined, undefined, new Date('2026-10-18T05:00:00Z'))!.from.toISOString()).toBe('2026-10-12T00:00:00.000Z');
  });

  it('counts findings, scores and hosts inside the period only', async () => {
    const inside = await buildReport(db, parsePeriod('2026-10-10', '2026-10-16')!);
    expect(inside.hosts).toEqual({ total: 1, reporting: 1 });
    expect(inside.findings.newBySev.critical).toBe(2);
    expect(sevTotal(inside.findings.openEndBySev)).toBe(2);
    expect(inside.findings.topNew).toHaveLength(2);
    expect(inside.score.end).not.toBeNull();
    expect(inside.score.lowest[0]?.agentId).toBe(A);
    const before = await buildReport(db, parsePeriod('2026-09-01', '2026-10-15')!);
    expect(sevTotal(before.findings.newBySev)).toBe(0);
    expect(before.hosts.reporting).toBe(0);
    // 限定主機
    const one = await buildReport(db, { ...parsePeriod('2026-10-10', '2026-10-16')!, agentId: A });
    expect(one.agent?.id).toBe(A);
    expect(one.findings.newBySev.critical).toBe(2);
  });

  it('writes highlights and Markdown', async () => {
    const r = await buildReport(db, parsePeriod('2026-10-10', '2026-10-16')!);
    const t = makeT('zh-TW');
    expect(highlights(r, t)[0]).toContain('新增 2 個問題');
    const md = toMarkdown(r, t);
    expect(md).toContain('# 資安報告');
    expect(md).toContain('2026-10-10 ～ 2026-10-16');
    expect(md).toContain('| 嚴重 |');
    expect(toMarkdown(r, makeT('en'))).toContain('# Security report');
  });

  it('serves Markdown and JSON downloads to admins only', async () => {
    const get = (q: string, token = 'test-admin') =>
      reportGet(new Request(`http://localhost:3000/api/v1/report?${q}`, { headers: { authorization: `Bearer ${token}` } }));
    const md = await get('from=2026-10-10&to=2026-10-16');
    expect(md.status).toBe(200);
    expect(md.headers.get('content-disposition')).toContain('security-report-2026-10-10_2026-10-16.md');
    const js = await (await get('from=2026-10-10&to=2026-10-16&format=json')).json();
    expect(js.findings.newBySev.critical).toBe(2);
    expect((await get('from=2026-10-17&to=2026-10-16')).status).toBe(400);
    expect((await get('from=2026-10-10&to=2026-10-16', 'client-a')).status).toBe(401);
  });
});
