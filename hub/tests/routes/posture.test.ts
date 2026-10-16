import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { POST as mcpPost } from '@/app/api/mcp/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { GET as hardeningGet } from '@/app/api/v1/hardening/route';
import { POST as report } from '@/app/api/v1/ingest/report/route';
import { GET as vulnsGet } from '@/app/api/v1/vulns/route';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { resetEnvForTests } from '@/lib/env';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { agentHardening, agentVuln, hardeningOverview, vulnOverview } from '@/lib/queries/posture';
import { createTestDb } from '../helpers/db';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const A = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
const B = '1f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';

function post(pathname: string, body: unknown, agentToken?: string) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer client-a', ...(agentToken ? { 'x-asa-agent-token': agentToken } : {}) },
    body: JSON.stringify(body),
  });
}

const admin = (url: string) => new Request(`http://localhost:3000${url}`, { headers: { authorization: 'Bearer test-admin' } });

function vuln(product: string, status: string, hits: unknown[], extra: Record<string, unknown> = {}) {
  return {
    os: { family: 'windows', name: 'Microsoft Windows 10 Pro', version: '22H2', build: 19045 },
    support: { product, eol: '2025-10-14', status, days_left: -368 },
    last_patch: { date: '2026-01-02', id: 'KB5050000', days: 288 },
    packages: 140,
    by_ecosystem: { windows: 140 },
    app_hits: hits,
    kev_count: 1,
    notes: [],
    ...extra,
  };
}

const sevenZip = (installed: string) => ({
  rule_id: '7zip-cve-2025-0411',
  app: '7-Zip',
  installed_name: `7-Zip ${installed} (x64)`,
  installed,
  fixed: '24.09',
  cves: ['CVE-2025-0411'],
  kev: ['CVE-2025-0411'],
  severity: 'critical',
  eol: false,
  summary: 'MotW bypass',
  fix: 'Update 7-Zip',
  reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0411',
});

function hardening(score: number, fails: string[]) {
  const ids = ['win.uac.enabled', 'win.bitlocker.system', 'win.secureboot', 'win.llmnr.disabled'];
  return {
    os_family: 'windows',
    pass: ids.length - fails.length,
    fail: fails.length,
    na: 0,
    error: 0,
    score,
    needs_admin: [],
    results: ids.map((id) => ({
      id,
      category: 'x',
      severity: id.includes('bitlocker') ? 'high' : 'low',
      title: id,
      result: fails.includes(id) ? 'fail' : 'pass',
      observed: fails.includes(id) ? 'off' : 'on',
      expected: '= on',
      remediation: `fix ${id}`,
      rationale: '',
      references: ['https://learn.microsoft.com/'],
    })),
  };
}

async function enroll(agentId: string, hostname: string, summaries: Record<string, unknown>) {
  const reg = load('register.v1.json');
  reg.agent_id = agentId;
  reg.agent.id = agentId;
  reg.agent.hostname = hostname;
  const token = `tok-${hostname}-0123456789abcdef0123`;
  expect((await register(post('/api/v1/agents/register', reg, token))).status).toBe(200);
  const r = load('report.v1.json');
  r.report_id = crypto.randomUUID();
  r.agent.id = agentId;
  r.agent.hostname = hostname;
  r.finished_at = new Date().toISOString();
  r.summaries = summaries;
  const req = post('/api/v1/ingest/report', r, token);
  req.headers.set('x-asa-agent-id', agentId);
  const res = await report(req);
  expect(res.status, await res.clone().text()).toBe(200);
}

beforeAll(async () => {
  await createTestDb();
});

beforeEach(() => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
  delete process.env.ASA_HUB_MCP_TOKEN;
  resetEnvForTests();
  resetThrottleForTests();
  resetRateLimitsForTests();
});

describe('vulnerability and hardening posture', () => {
  it('aggregates the latest summaries across hosts', async () => {
    await enroll(A, 'pc-a', { vuln: vuln('Windows 10 22H2', 'eol', [sevenZip('24.08')]), hardening: hardening(60, ['win.bitlocker.system', 'win.llmnr.disabled']) });
    await enroll(B, 'pc-b', {
      vuln: vuln('Windows 11 25H2', 'supported', [sevenZip('23.01')], { last_patch: { date: '2026-10-16', id: 'KB5127648', days: 1 }, kev_count: 0, app_hits: [{ ...sevenZip('23.01'), kev: [], severity: 'high' }] }),
      hardening: hardening(90, ['win.llmnr.disabled']),
    });
    const v = await vulnOverview();
    expect(v).toMatchObject({ hosts: 2, unsupported: 1, endingSoon: 0, kevHosts: 1, stalePatches: 1 });
    expect(v.os[0]).toMatchObject({ hostname: 'pc-a', support: { status: 'eol' } });
    expect(v.apps).toHaveLength(1);
    expect(v.apps[0].hit.severity).toBe('critical');
    expect(v.apps[0].hosts.map((h) => h.installed).sort()).toEqual(['23.01', '24.08']);

    const h = await hardeningOverview();
    expect(h.average).toBe(75);
    expect(h.hosts.map((x) => x.hostname)).toEqual(['pc-a', 'pc-b']);
    expect(h.topFailed[0]).toMatchObject({ check: { id: 'win.llmnr.disabled' }, checked: 2 });
    expect(h.topFailed[0].hosts).toHaveLength(2);

    expect((await agentVuln(A))?.summary.app_hits[0].kev).toEqual(['CVE-2025-0411']);
    expect((await agentHardening(B))?.summary.score).toBe(90);
    expect(await agentVuln('nope')).toBeNull();
  });

  it('tolerates malformed summaries', async () => {
    await enroll(B, 'pc-b', { vuln: { os: 'bad', app_hits: [{ rule_id: 1 }], packages: 'x' }, hardening: { results: 'nope', score: 'high' } });
    const v = await agentVuln(B);
    expect(v?.summary.packages).toBe(0);
    expect(v?.summary.support ?? null).toBeNull();
    const h = await agentHardening(B);
    expect(h?.summary.results).toEqual([]);
    expect(h?.summary.score).toBeNull();
    expect((await hardeningOverview()).hosts.find((x) => x.hostname === 'pc-b')?.score).toBeNull();
  });

  it('serves the API and MCP tools', async () => {
    const v = await (await vulnsGet(admin('/api/v1/vulns'))).json();
    expect(v.hosts).toBe(2);
    expect((await vulnsGet(admin(`/api/v1/vulns?agent_id=${A}`))).status).toBe(200);
    expect((await vulnsGet(admin('/api/v1/vulns?agent_id=missing'))).status).toBe(404);
    expect((await hardeningGet(new Request('http://localhost:3000/api/v1/hardening'))).status).toBe(401);
    const h = await (await hardeningGet(admin(`/api/v1/hardening?agent_id=${A}`))).json();
    expect(h.summary.fail).toBe(2);

    const call = async (name: string, args: unknown = {}) => {
      const r = await mcpPost(
        new Request('http://localhost:3000/api/mcp', {
          method: 'POST',
          headers: { 'content-type': 'application/json', host: 'localhost:3000', authorization: 'Bearer test-admin' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
        }),
      );
      return JSON.parse((await r.json()).result.content[0].text);
    };
    expect((await call('vuln_overview')).unsupported).toBe(1);
    const one = await call('hardening_overview', { agent_id: A, only_failed: true });
    expect(one.summary.results.map((o: { id: string }) => o.id)).toEqual(['win.bitlocker.system', 'win.llmnr.disabled']);
    // pc-b 的硬化資料已被上一個測試換成壞資料：只剩 pc-a 的兩項，高嚴重度排前面
    expect((await call('hardening_overview')).top_failed.map((e: { id: string }) => e.id)).toEqual(['win.bitlocker.system', 'win.llmnr.disabled']);
  });
});
