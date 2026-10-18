// 集中設定：群組設定驗證與合併、心跳帶版本、agent 取設定（驗章、權限）；以及部分更新不會把沒送的欄位洗成預設值。
import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { beforeAll, describe, expect, it } from 'vitest';
import { POST as groupPost } from '@/app/api/v1/admin/groups/route';
import { PUT as groupPut } from '@/app/api/v1/admin/groups/[id]/route';
import { PUT as notifyRulePut } from '@/app/api/v1/admin/notifications/rules/[id]/route';
import { POST as notifyRulePost } from '@/app/api/v1/admin/notifications/rules/route';
import { POST as channelPost } from '@/app/api/v1/admin/notifications/channels/route';
import { PUT as responseRulePut } from '@/app/api/v1/admin/response/rules/[id]/route';
import { POST as responseRulePost } from '@/app/api/v1/admin/response/rules/route';
import { GET as configGet } from '@/app/api/v1/agents/me/config/route';
import { POST as heartbeat } from '@/app/api/v1/agents/me/heartbeat/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { agentGroupMembers, notificationRules, responseRules } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { configMessage, mergeConfigs } from '@/lib/central/config';
import type { DB } from '@/lib/db';
import { hubIdentity, verifyWithRawKey } from '@/lib/enroll/identity';
import { resetEnvForTests } from '@/lib/env';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const admin = { authorization: 'Bearer test-admin' };
const AGENT = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
const TOKEN = 'agent-token-0123456789abcdef0123456789abcdef';
const ctx = (id: string) => ({ params: Promise.resolve({ id }) });

function agentReq(pathname: string, init: { method?: string; body?: unknown; token?: string } = {}) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: init.method ?? 'GET',
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer client-a',
      'x-asa-agent-id': AGENT,
      'x-asa-agent-token': init.token ?? TOKEN,
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

async function idOf(r: Response): Promise<string> {
  expect(r.status).toBe(201);
  return ((await r.json()) as { id: string }).id;
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_SNAPSHOT_MIN_INTERVAL_MS = '0';
  resetEnvForTests();
  // 註冊時帶 agent token → 釘選
  expect((await register(agentReq('/api/v1/agents/register', { method: 'POST', body: load('register.v1.json') }))).status).toBeLessThan(300);
});

describe('central config', () => {
  it('merges groups by name: later scalars win, lists are combined', () => {
    expect(
      mergeConfigs([
        { scan_interval: '10m', fim_ignore: ['/a'] },
        { scan_interval: '30m', fim_ignore: ['/a', '/b'], dns_names: false },
      ]),
    ).toEqual({ scan_interval: '30m', fim_ignore: ['/a', '/b'], dns_names: false });
  });

  it('rejects unsafe or out-of-range settings', async () => {
    const bad = async (config: unknown) =>
      (await groupPost(req('/api/v1/admin/groups', { method: 'POST', body: { name: 'x', config }, headers: admin }))).status;
    expect(await bad({ scan_interval: '1m' })).toBe(400);
    expect(await bad({ snapshot_interval: '5s' })).toBe(400);
    expect(await bad({ metrics_performance: true })).toBe(400);
    expect(await bad({ remote_actions: { accept: true } })).toBe(400);
  });

  it('tells the agent the version on heartbeat and serves a config signed with the hub identity', async () => {
    resetRateLimitsForTests();
    resetThrottleForTests();
    const hb = async () =>
      (await (await heartbeat(agentReq('/api/v1/agents/me/heartbeat', { method: 'POST', body: { agent_id: AGENT, ts: new Date().toISOString(), version: '0.6.0', elevated: false } }))).json()) as {
        config_version: string | null;
      };
    expect((await hb()).config_version).toBeNull();
    expect(await (await configGet(agentReq('/api/v1/agents/me/config'))).json()).toEqual({ version: null, groups: [] });

    const a = await idOf(await groupPost(req('/api/v1/admin/groups', { method: 'POST', body: { name: 'b-servers', members: [AGENT], config: { scan_interval: '30m', fim_ignore: ['/b'] } }, headers: admin })));
    await idOf(await groupPost(req('/api/v1/admin/groups', { method: 'POST', body: { name: 'a-all', members: [AGENT], config: { scan_interval: '15m', fim_ignore: ['/a'], dns_names: false } }, headers: admin })));
    resetThrottleForTests();
    const v = (await hb()).config_version;
    expect(v).toMatch(/^[0-9a-f]{16}$/);

    const r = (await (await configGet(agentReq('/api/v1/agents/me/config'))).json()) as { version: string; config_json: string; signature: string; groups: string[] };
    expect(r.version).toBe(v);
    expect(r.groups).toEqual(['a-all', 'b-servers']);
    expect(JSON.parse(r.config_json)).toEqual({ dns_names: false, fim_ignore: ['/a', '/b'], scan_interval: '30m' });
    const id = await hubIdentity(db);
    expect(verifyWithRawKey(id.publicKeyB64, configMessage(AGENT, r.version, r.config_json), r.signature)).toBe(true);
    // 改到另一台的訊息、竄改內容都驗不過
    expect(verifyWithRawKey(id.publicKeyB64, configMessage('other-agent', r.version, r.config_json), r.signature)).toBe(false);
    expect(verifyWithRawKey(id.publicKeyB64, configMessage(AGENT, r.version, r.config_json.replace('30m', '5m')), r.signature)).toBe(false);

    // 只改群組名稱：成員與設定都保留
    expect((await groupPut(req(`/api/v1/admin/groups/${a}`, { method: 'PUT', body: { name: 'b-servers-2' }, headers: admin }), ctx(a))).status).toBe(200);
    expect((await db.select().from(agentGroupMembers).where(eq(agentGroupMembers.groupId, a))).length).toBe(1);
    resetThrottleForTests();
    expect((await hb()).config_version).toBe(v);
  });

  it('refuses agents with a wrong token or a key for another agent', async () => {
    expect((await configGet(agentReq('/api/v1/agents/me/config', { token: 'wrong-token-0123456789abcdef0123456789ab' }))).status).toBe(403);
    expect((await configGet(req('/api/v1/agents/me/config', { headers: admin }))).status).toBe(401);
  });
});

describe('partial updates keep fields that were not sent', () => {
  it('toggling an auto-response rule keeps its threshold, duration and finding rule', async () => {
    const id = await idOf(
      await responseRulePost(req('/api/v1/admin/response/rules', { method: 'POST', body: { name: 'f', trigger: 'finding', params: { rule: 'intel.*' }, blockMinutes: 120, escalate: false }, headers: admin })),
    );
    expect((await responseRulePut(req(`/api/v1/admin/response/rules/${id}`, { method: 'PUT', body: { enabled: false }, headers: admin }), ctx(id))).status).toBe(200);
    expect((await db.select().from(responseRules).where(eq(responseRules.id, id)))[0]).toMatchObject({ enabled: false, blockMinutes: 120, escalate: false, params: { rule: 'intel.*' } });
  });

  it('toggling a notification rule keeps its parameters', async () => {
    const ch = await idOf(await channelPost(req('/api/v1/admin/notifications/channels', { method: 'POST', body: { kind: 'slack', name: 's', config: { url: 'https://hooks.example.com/x' } }, headers: admin })));
    const id = await idOf(await notifyRulePost(req('/api/v1/admin/notifications/rules', { method: 'POST', body: { name: 'o', event: 'host_offline', params: { minutes: 90 }, channelIds: [ch] }, headers: admin })));
    expect((await notifyRulePut(req(`/api/v1/admin/notifications/rules/${id}`, { method: 'PUT', body: { enabled: false }, headers: admin }), ctx(id))).status).toBe(200);
    expect((await db.select().from(notificationRules).where(eq(notificationRules.id, id)))[0]).toMatchObject({ enabled: false, params: { minutes: 90 }, channelIds: [ch] });
  });
});
