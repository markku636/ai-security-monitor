import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { DELETE as mcpDelete, GET as mcpGet, POST as mcpPost } from '@/app/api/mcp/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { POST as report } from '@/app/api/v1/ingest/report/route';
import { POST as snapshot } from '@/app/api/v1/ingest/snapshot/route';
import { agentSummaries, crashRecords, securityEvents } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { bruteForceSources, crashCounts, latestSummary, recentCrashes, securityHits, topBugchecks } from '@/lib/queries/events';
import { newDestinations, processActivity, topDestinations } from '@/lib/queries/traffic';
import { createTestDb } from '../helpers/db';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const AGENT = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
const now = Date.now();
const iso = (minsAgo: number) => new Date(now - minsAgo * 60_000).toISOString();

function clientPost(pathname: string, body: unknown) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer client-a' },
    body: JSON.stringify(body),
  });
}

function eventsSummary(failedCount: number) {
  return {
    platform: 'windows',
    days: 7,
    events_read: 120,
    counts_by_level: { error: 10 },
    crash_counts: { bugcheck: 1, app_crash: 1 },
    crashes: [
      {
        kind: 'bugcheck',
        time: iso(60),
        code: '0x00000124',
        name: 'WHEA_UNCORRECTABLE_ERROR',
        params: ['0x0'],
        likely_causes: ['CPU', 'RAM'],
        remediation: 'Restore BIOS defaults',
        source: 'System/Microsoft-Windows-Kernel-Power#41',
      },
      { kind: 'app_crash', time: iso(30), code: '0xc0000005', name: 'game.exe', module: 'nvwgf2umx.dll', process: 'game.exe', source: 'Application/Application Error#1000' },
      { kind: 'nonsense', time: 'not a date' },
    ],
    security: [
      {
        rule: 'failed_logon_burst',
        severity: 'high',
        count: failedCount,
        first: iso(120),
        last: iso(5),
        source_ip: '185.199.108.9',
        detail: 'max 12 in 10 min',
        intel: [{ feed_id: 'blocklist-de-all', vendor: 'blocklist.de', confidence: 80, source_url: 'https://lists.blocklist.de/lists/all.txt' }],
        samples: [],
      },
      { rule: 'service_installed', severity: 'low', count: 1, first: iso(200), last: iso(200), detail: 'Claude → C:\\Program Files\\WindowsApps\\x.exe' },
    ],
    top_error_sources: [{ provider: 'Service Control Manager', event_id: 7031, level: 'error', count: 9, sample: 'Cloudflared agent terminated' }],
    needs_admin: ['Minidump'],
    notes: [],
  };
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
});

beforeEach(() => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
  process.env.ASA_HUB_SNAPSHOT_MIN_INTERVAL_MS = '0';
  delete process.env.ASA_HUB_MCP_TOKEN;
  resetEnvForTests();
  resetThrottleForTests();
  resetRateLimitsForTests();
});

describe('events summaries', () => {
  it('stores crashes and security events from report summaries, de-duplicating across reports', async () => {
    await register(clientPost('/api/v1/agents/register', load('register.v1.json')));
    const r1 = load('report.v1.json');
    r1.finished_at = new Date().toISOString();
    r1.summaries = { events: eventsSummary(12) };
    expect((await report(clientPost('/api/v1/ingest/report', r1))).status).toBe(200);
    expect(await db.select().from(crashRecords)).toHaveLength(2);
    // 下一份報告（滾動視窗）：同樣的當機不重複、失敗次數變多
    const r2 = structuredClone(r1);
    r2.report_id = '11111111-2222-4333-8444-555555555555';
    r2.finished_at = new Date(Date.now() + 1000).toISOString();
    r2.summaries = { events: eventsSummary(40), vuln: { packages: 140, support: { product: 'Windows 11 25H2', status: 'supported' }, app_hits: [] }, hardening: { pass: 15, fail: 4, na: 1, error: 0, score: 81, results: [] } };
    expect((await report(clientPost('/api/v1/ingest/report', r2))).status).toBe(200);
    expect(await db.select().from(crashRecords)).toHaveLength(2);
    const sec = await db.select().from(securityEvents);
    expect(sec).toHaveLength(2);
    expect(sec.find((s) => s.rule === 'failed_logon_burst')?.count).toBe(40);
    const summ = await db.select().from(agentSummaries);
    expect(summ[0]).toMatchObject({ kind: 'events' });
    expect((await latestSummary(AGENT, 'events'))?.summary).toMatchObject({ needs_admin: ['Minidump'] });
    expect((await latestSummary(AGENT, 'vuln'))?.summary).toMatchObject({ packages: 140, support: { status: 'supported' } });
    expect((await latestSummary(AGENT, 'hardening'))?.summary).toMatchObject({ score: 81, fail: 4 });
  });

  it('answers the events queries', async () => {
    expect(await crashCounts(30)).toMatchObject({ bugcheck: { count: 1, hosts: 1 }, app_crash: { count: 1 } });
    const bugs = await topBugchecks(30);
    expect(bugs[0]).toMatchObject({ code: '0x00000124', name: 'WHEA_UNCORRECTABLE_ERROR', count: 1 });
    const crashes = await recentCrashes({ days: 30 });
    expect(crashes[0].kind).toBe('app_crash');
    expect((crashes[1].details as { likely_causes: string[] }).likely_causes).toEqual(['CPU', 'RAM']);
    const brute = await bruteForceSources(30);
    expect(brute[0]).toMatchObject({ sourceIp: '185.199.108.9', attempts: 40, hosts: 1 });
    expect(brute[0].intel[0].vendor).toBe('blocklist.de');
    expect(await securityHits({ minSeverity: 'medium' })).toHaveLength(1);
    expect(await securityHits({})).toHaveLength(2);
  });

  it('answers the traffic queries from snapshots', async () => {
    // 契約範例的 ts 是固定日期；「最近 24 小時的新目的地」要以現在為準，否則過了那天就失敗
    await snapshot(clientPost('/api/v1/ingest/snapshot', { ...load('snapshot.v1.json'), ts: new Date().toISOString() }));
    const top = await topDestinations({ days: 7 });
    expect(top[0]).toMatchObject({ remoteIp: '203.0.113.66', worstVerdict: 'dangerous' });
    expect(await topDestinations({ days: 7, risky: true })).toHaveLength(1);
    expect((await newDestinations(24)).length).toBe(1);
    const procs = await processActivity();
    expect(procs[0]).toMatchObject({ process: 'updater.exe', conns: 1, risky: 1 });
  });
});

describe('hub MCP', () => {
  const call = (body: unknown, headers: Record<string, string> = { authorization: 'Bearer test-admin' }) =>
    mcpPost(new Request('http://localhost:3000/api/mcp', { method: 'POST', headers: { 'content-type': 'application/json', host: 'localhost:3000', ...headers }, body: JSON.stringify(body) }));

  it('requires the admin key or the MCP token', async () => {
    expect((await call({ jsonrpc: '2.0', id: 1, method: 'initialize' }, {})).status).toBe(401);
    expect((await call({ jsonrpc: '2.0', id: 1, method: 'initialize' }, { authorization: 'Bearer client-a' })).status).toBe(401);
    process.env.ASA_HUB_MCP_TOKEN = 'mcp-token';
    expect((await call({ jsonrpc: '2.0', id: 1, method: 'initialize' }, { authorization: 'Bearer mcp-token' })).status).toBe(200);
    // 開放模式：只接受本機
    delete process.env.ASA_HUB_ADMIN_SECRET;
    delete process.env.ASA_HUB_CLIENT_SECRETS;
    resetEnvForTests();
    expect((await call({ jsonrpc: '2.0', id: 1, method: 'initialize' }, { host: 'evil.example' })).status).toBe(401);
    expect((await call({ jsonrpc: '2.0', id: 1, method: 'initialize' }, { origin: 'https://evil.example' })).status).toBe(401);
    expect((await call({ jsonrpc: '2.0', id: 1, method: 'initialize' }, {})).status).toBe(200);
    expect((await mcpGet()).status).toBe(405);
  });

  it('lists and runs read-only tools with sessions', async () => {
    const init = await call({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
    const sid = init.headers.get('mcp-session-id')!;
    expect((await init.json()).result.protocolVersion).toBe('2025-03-26');
    const s = { authorization: 'Bearer test-admin', 'mcp-session-id': sid };
    const list = await (await call({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, s)).json();
    expect(list.result.tools.map((t: { name: string }) => t.name)).toContain('crash_history');
    const text = async (name: string, args: unknown = {}) => {
      const r = await (await call({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name, arguments: args } }, s)).json();
      return r.result as { isError: boolean; content: { text: string }[] };
    };
    expect(JSON.parse((await text('fleet_summary')).content[0].text).agents.total).toBe(1);
    const brute = JSON.parse((await text('brute_force_sources')).content[0].text);
    expect(brute[0].sourceIp).toBe('185.199.108.9');
    const bug = await text('explain_bugcheck', { code: '0x124' });
    expect(JSON.parse(bug.content[0].text).name).toBe('WHEA_UNCORRECTABLE_ERROR');
    expect((await text('explain_bugcheck', { code: 'zzz' })).isError).toBe(true);
    expect((await text('nope')).isError).toBe(true);
    const findings = JSON.parse((await text('list_findings', { severity: ['critical'] })).content[0].text);
    expect(findings.total).toBe(2);
    const conns = JSON.parse((await text('list_connections', { verdict: ['dangerous'] })).content[0].text);
    expect(conns.items[0].remoteIp).toBe('203.0.113.66');
    // 統計工具：AI 不用自己數
    const stats = JSON.parse((await text('connection_stats', { verdict: ['dangerous'] })).content[0].text);
    expect(stats.total).toBeGreaterThan(0);
    expect(stats.by_verdict.groups).toEqual([{ key: 'dangerous', count: stats.total }]);
    expect(stats.by_remote_ip.groups[0].key).toBe('203.0.113.66');
    expect(stats.by_host.groups[0].count).toBe(stats.total);
    // 通知 → 202；未知 session → 404；DELETE 結束 session
    expect((await call({ jsonrpc: '2.0', method: 'notifications/initialized' }, s)).status).toBe(202);
    expect((await call({ jsonrpc: '2.0', id: 9, method: 'ping' }, { authorization: 'Bearer test-admin', 'mcp-session-id': 'nope' })).status).toBe(404);
    const del = await mcpDelete(new Request('http://localhost:3000/api/mcp', { method: 'DELETE', headers: s }));
    expect(del.status).toBe(200);
  });
});
