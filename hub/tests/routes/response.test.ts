// 自動回應：預設關、只封公網＋不在白名單、只對同意遠端動作的主機、不重複、到期自動解除、重複觸犯加長、群組範圍、管理 API。
import fs from 'node:fs';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { POST as groupPost } from '@/app/api/v1/admin/groups/route';
import { DELETE as groupDelete } from '@/app/api/v1/admin/groups/[id]/route';
import { GET as responseGet, PUT as responsePut } from '@/app/api/v1/admin/response/route';
import { POST as releasePost } from '@/app/api/v1/admin/response/blocks/[id]/release/route';
import { POST as rulePost } from '@/app/api/v1/admin/response/rules/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { actions, agents, auditLog, responseBlocks, responseRules, securityEvents, settings } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { ruleMatches, runAutoResponse } from '@/lib/response/engine';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const admin = { authorization: 'Bearer test-admin' };
const AGENT = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
const ATTACKER = '45.155.205.233';

function clientPost(pathname: string, body: unknown) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer client-a' },
    body: JSON.stringify(body),
  });
}

async function json<T>(r: Response): Promise<T> {
  return (await r.json()) as T;
}

async function setSettings(body: unknown) {
  return responsePut(req('/api/v1/admin/response', { method: 'PUT', body, headers: admin }));
}

async function addRule(body: unknown): Promise<string> {
  const r = await rulePost(req('/api/v1/admin/response/rules', { method: 'POST', body, headers: admin }));
  expect(r.status).toBe(201);
  return (await json<{ id: string }>(r)).id;
}

async function bruteforce(ip: string, n = 25, at = new Date()) {
  await db.insert(securityEvents).values({ agentId: AGENT, rule: 'failed_logon_burst', severity: 'high', count: n, firstAt: at, lastAt: at, sourceIp: ip, dedupeKey: `bf-${ip}-${at.getTime()}` });
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  resetEnvForTests();
  await register(clientPost('/api/v1/agents/register', load('register.v1.json')));
});

beforeEach(async () => {
  resetRateLimitsForTests();
  await db.delete(responseBlocks);
  await db.delete(responseRules);
  await db.delete(actions);
  await db.delete(securityEvents);
  await db.delete(auditLog);
  await db.delete(settings).where(eq(settings.key, 'response.settings'));
  await db.update(agents).set({ acceptRemoteActions: true }).where(eq(agents.id, AGENT));
});

describe('auto-response engine', () => {
  it('does nothing while switched off (the default)', async () => {
    await addRule({ name: 'bf', trigger: 'bruteforce', params: { threshold: 10 } });
    await bruteforce(ATTACKER);
    expect(await runAutoResponse(db)).toEqual({ blocked: 0, released: 0, skipped: 0 });
    expect(await db.select().from(actions)).toEqual([]);
  });

  it('blocks a brute-force source with an approved, expiring action, once, then releases it and escalates repeats', async () => {
    expect((await setSettings({ enabled: true })).status).toBe(200);
    const ruleId = await addRule({ name: 'bf', trigger: 'bruteforce', params: { threshold: 10 }, blockMinutes: 60 });
    await bruteforce(ATTACKER);
    await bruteforce('8.8.8.8', 3); // 低於門檻
    const t0 = new Date();
    expect(await runAutoResponse(db, t0)).toMatchObject({ blocked: 1 });
    const [a] = await db.select().from(actions);
    expect(a).toMatchObject({ kind: 'block_ip', status: 'approved', proposedBy: `auto:${ruleId}`, reviewedBy: `auto:${ruleId}` });
    expect(a.params).toMatchObject({ ip: ATTACKER, direction: 'both' });
    const [b] = await db.select().from(responseBlocks);
    expect(b).toMatchObject({ ip: ATTACKER, status: 'active', level: 0 });
    expect(b.expiresAt.getTime() - b.blockedAt.getTime()).toBe(60 * 60_000);
    expect((await db.select().from(auditLog).where(eq(auditLog.action, 'response.blocked'))).length).toBe(1);

    // 已經封著：不重複
    expect((await runAutoResponse(db, new Date(t0.getTime() + 60_000))).blocked).toBe(0);
    // 到期：自動解除
    const later = new Date(t0.getTime() + 61 * 60_000);
    expect((await runAutoResponse(db, later)).released).toBe(1);
    const unblock = (await db.select().from(actions)).find((x) => x.kind === 'unblock_ip')!;
    expect(unblock).toMatchObject({ status: 'approved', params: { ip: ATTACKER } });
    expect((await db.select().from(responseBlocks))[0].status).toBe('released');
    // 同一個來源又出現：第二次 ×6
    await db.delete(actions);
    expect((await runAutoResponse(db, new Date(later.getTime() + 60_000))).blocked).toBe(1);
    const second = (await db.select().from(responseBlocks)).find((x) => x.status === 'active')!;
    expect(second.level).toBe(1);
    expect(second.expiresAt.getTime() - second.blockedAt.getTime()).toBe(360 * 60_000);
  });

  it('never blocks private or allowlisted addresses, or hosts that did not agree to remote actions', async () => {
    await setSettings({ enabled: true, allowlist: ['203.0.113.0/24'] });
    await addRule({ name: 'bf', trigger: 'bruteforce', params: { threshold: 10 } });
    await bruteforce('10.1.2.3');
    await bruteforce('203.0.113.9');
    expect(await runAutoResponse(db)).toMatchObject({ blocked: 0, skipped: 2 });
    await db.update(agents).set({ acceptRemoteActions: false }).where(eq(agents.id, AGENT));
    await bruteforce(ATTACKER);
    expect((await runAutoResponse(db)).blocked).toBe(0);
  });

  it('limits a rule to a host group, and deleting the group disables that rule', async () => {
    await setSettings({ enabled: true });
    const g = await groupPost(req('/api/v1/admin/groups', { method: 'POST', body: { name: 'Servers', members: [] }, headers: admin }));
    const groupId = (await json<{ id: string }>(g)).id;
    const ruleId = await addRule({ name: 'servers only', trigger: 'bruteforce', params: { threshold: 10 }, groupId });
    await bruteforce(ATTACKER);
    expect((await runAutoResponse(db)).blocked).toBe(0);
    expect((await groupDelete(req(`/api/v1/admin/groups/${groupId}`, { method: 'DELETE', headers: admin }), { params: Promise.resolve({ id: groupId }) })).status).toBe(200);
    expect((await db.select().from(responseRules).where(eq(responseRules.id, ruleId)))[0]).toMatchObject({ enabled: false, groupId: null });
  });

  it('matches finding rule patterns', () => {
    expect(ruleMatches('intel.inbound_match', 'intel.inbound_match')).toBe(true);
    expect(ruleMatches('intel.*', 'intel.inbound_match')).toBe(true);
    expect(ruleMatches('intel.*', 'ports.exposed_open')).toBe(false);
  });
});

describe('admin API', () => {
  it('needs admin, validates settings and rules, lists blocks, and releases on demand', async () => {
    expect((await responseGet(req('/api/v1/admin/response', { headers: { authorization: 'Bearer client-a' } }))).status).toBe(401);
    expect((await setSettings({ allowlist: ['not-a-cidr'] })).status).toBe(400);
    expect((await rulePost(req('/api/v1/admin/response/rules', { method: 'POST', body: { name: 'f', trigger: 'finding' }, headers: admin }))).status).toBe(400);
    expect((await rulePost(req('/api/v1/admin/response/rules', { method: 'POST', body: { name: 'x', trigger: 'bruteforce', groupId: 'nope' }, headers: admin }))).status).toBe(400);

    await setSettings({ enabled: true });
    await addRule({ name: 'bf', trigger: 'bruteforce', params: { threshold: 10 } });
    await bruteforce(ATTACKER);
    await runAutoResponse(db);
    const view = await json<{ blocks: { id: string; hostname: string; ip: string; status: string }[]; settings: { enabled: boolean } }>(
      await responseGet(req('/api/v1/admin/response', { headers: admin })),
    );
    expect(view.settings.enabled).toBe(true);
    expect(view.blocks[0]).toMatchObject({ hostname: 'demo-host', ip: ATTACKER, status: 'active' });
    const id = view.blocks[0].id;
    expect((await releasePost(req(`/api/v1/admin/response/blocks/${id}/release`, { method: 'POST', headers: admin }), { params: Promise.resolve({ id }) })).status).toBe(200);
    expect((await db.select().from(responseBlocks))[0].status).toBe('released');
    const audits = await db.select().from(auditLog).where(eq(auditLog.action, 'response.released'));
    expect(audits[0]).toMatchObject({ actor: 'admin:bearer', actorRole: 'admin' });
  });
});
