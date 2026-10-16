import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { POST as decide } from '@/app/api/v1/actions/[id]/route';
import { GET as listRoute, POST as createRoute } from '@/app/api/v1/actions/route';
import { POST as resultRoute } from '@/app/api/v1/agents/me/actions/[id]/result/route';
import { GET as pollRoute } from '@/app/api/v1/agents/me/actions/route';
import { POST as heartbeat } from '@/app/api/v1/agents/me/heartbeat/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { POST as report } from '@/app/api/v1/ingest/report/route';
import { actions, auditLog } from '@/drizzle/schema';
import { actionKeyFor, signingKey, tokenFor } from '@/lib/actions/sign';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const AGENT = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
const TOKEN = 'agent-token-0123456789abcdef0123456789abcdef';
const admin = { authorization: 'Bearer test-admin' };

function agentReq(method: string, pathname: string, body?: unknown, token: string | null = TOKEN) {
  const headers: Record<string, string> = { authorization: 'Bearer client-a', 'x-asa-agent-id': AGENT };
  if (token) headers['x-asa-agent-token'] = token;
  if (body !== undefined) headers['content-type'] = 'application/json';
  return new Request(`http://localhost:3000${pathname}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
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
  resetEnvForTests();
  resetThrottleForTests();
  resetRateLimitsForTests();
});

const create = (body: unknown) => createRoute(req('/api/v1/actions', { method: 'POST', headers: admin, body }));
const decideReq = (id: string, body: unknown) => decide(req(`/api/v1/actions/${id}`, { method: 'POST', headers: admin, body }), { params: Promise.resolve({ id }) });
const poll = (token: string | null = TOKEN) => pollRoute(agentReq('GET', '/api/v1/agents/me/actions', undefined, token));

describe('agent identity pinning', () => {
  it('pins the agent token on register and hands out the action key only then', async () => {
    const reg = load('register.v1.json');
    reg.accept_remote_actions = true;
    const r = await (await register(agentReq('POST', '/api/v1/agents/register', reg))).json();
    expect(r.pinned).toBe(true);
    expect(r.action_key).toBe(actionKeyFor(await signingKey(db), AGENT));

    // 冒名：同一把 client 金鑰、同一個 agent id，但 token 不對 / 沒帶
    expect((await register(agentReq('POST', '/api/v1/agents/register', reg, 'someone-else-token-000000'))).status).toBe(403);
    expect((await register(agentReq('POST', '/api/v1/agents/register', reg, null))).status).toBe(403);
    expect((await report(agentReq('POST', '/api/v1/ingest/report', load('report.v1.json'), null))).status).toBe(403);
    expect((await report(agentReq('POST', '/api/v1/ingest/report', load('report.v1.json')))).status).toBe(200);
    const audits = await db.select().from(auditLog).where(eq(auditLog.action, 'ingest.register.token_mismatch'));
    expect(audits.length).toBe(2);
  });
});

describe('remote actions', () => {
  it('validates proposals', async () => {
    expect((await create({ agent_id: AGENT, kind: 'block_ip', params: { ip: '127.0.0.1' } })).status).toBe(400);
    const broad = await create({ agent_id: AGENT, kind: 'block_ip', params: { ip: '10.0.0.0/8' } });
    expect((await broad.json()).error).toBe('target_too_broad');
    expect((await create({ agent_id: 'ghost', kind: 'block_ip', params: { ip: '198.51.100.7' } })).status).toBe(404);
    expect((await create({ agent_id: AGENT, kind: 'format_disk', params: {} })).status).toBe(400);
  });

  it('pending → approved → dispatched (signed) → succeeded', async () => {
    const c = await create({ agent_id: AGENT, kind: 'block_ip', params: { ip: '203.0.113.66', reason: 'abusech-feodo' }, finding_id: 'f_x' });
    expect(c.status).toBe(201);
    const { action } = await c.json();
    expect(action.status).toBe('pending');
    expect((await create({ agent_id: AGENT, kind: 'block_ip', params: { reason: 'abusech-feodo', ip: '203.0.113.66' } })).status).toBe(409);

    // 核准前 agent 拿不到
    expect((await (await poll()).json()).items).toEqual([]);
    const hb = await (await heartbeat(agentReq('POST', '/api/v1/agents/me/heartbeat', { agent_id: AGENT, ts: new Date().toISOString(), version: '0.1.0' }))).json();
    expect(hb.pending_actions).toBe(0);

    const ap = await decideReq(action.id, { decision: 'approve', note: 'C2' });
    expect(ap.status).toBe(200);
    const hb2 = await (await heartbeat(agentReq('POST', '/api/v1/agents/me/heartbeat', { agent_id: AGENT, ts: new Date().toISOString(), version: '0.1.0' }))).json();
    expect(hb2.pending_actions).toBe(1);

    expect((await poll('wrong-token-0000000000000000')).status).toBe(403);
    const got = await (await poll()).json();
    expect(got.items).toHaveLength(1);
    const it0 = got.items[0];
    const key = actionKeyFor(await signingKey(db), AGENT);
    expect(it0.token).toBe(tokenFor(key, { action_id: it0.action_id, agent_id: AGENT, kind: 'block_ip', params: it0.params, expires_at: it0.expires_at }));
    // 剛派送過，不會馬上重派
    expect((await (await poll()).json()).items).toEqual([]);

    const res = await resultRoute(agentReq('POST', `/api/v1/agents/me/actions/${action.id}/result`, { agent_id: AGENT, ok: true, output: 'blocked 1 net' }), {
      params: Promise.resolve({ id: action.id }),
    });
    expect(res.status).toBe(200);
    const row = (await db.select().from(actions).where(eq(actions.id, action.id)))[0];
    expect(row).toMatchObject({ status: 'succeeded', resultOk: true, resultOutput: 'blocked 1 net', reviewedBy: 'admin:bearer' });
    // 已完成的可以再提案同一件事
    expect((await create({ agent_id: AGENT, kind: 'block_ip', params: { ip: '203.0.113.66', reason: 'abusech-feodo' } })).status).toBe(201);
  });

  it('destructive actions need the hostname; agents that refuse actions cannot be approved', async () => {
    const { action } = await (await create({ agent_id: AGENT, kind: 'close_port', params: { proto: 'tcp', port: 6379 } })).json();
    expect(action.destructive).toBe(true);
    expect((await decideReq(action.id, { decision: 'approve' })).status).toBe(400);
    expect((await decideReq(action.id, { decision: 'approve', confirm_hostname: 'demo-host' })).status).toBe(200);
    const cancel = await decideReq(action.id, { decision: 'cancel' });
    expect((await cancel.json()).action.status).toBe('cancelled');
    expect((await decideReq(action.id, { decision: 'approve', confirm_hostname: 'demo-host' })).status).toBe(409);

    // 改成不接受遠端動作後重新註冊
    const reg = load('register.v1.json');
    reg.accept_remote_actions = false;
    const r = await (await register(agentReq('POST', '/api/v1/agents/register', reg))).json();
    expect(r.action_key).toBeUndefined();
    const { action: a2 } = await (await create({ agent_id: AGENT, kind: 'unblock_ip', params: { ip: '198.51.100.7' } })).json();
    const rej = await decideReq(a2.id, { decision: 'approve' });
    expect((await rej.json()).error).toBe('agent_does_not_accept_actions');
    expect((await decideReq(a2.id, { decision: 'reject', note: 'no' })).status).toBe(200);

    const list = await (await listRoute(req('/api/v1/actions?status=rejected,cancelled', { headers: admin }))).json();
    expect(list.items.map((x: { status: string }) => x.status).sort()).toEqual(['cancelled', 'rejected']);
    expect(list.items[0].hostname).toBe('demo-host');
  });
});
