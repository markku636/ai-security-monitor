import zlib from 'node:zlib';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GET as overview } from '@/app/api/v1/admin/webscan/route';
import { GET as artifactGet } from '@/app/api/v1/admin/webscan/artifacts/[id]/route';
import { POST as findingsPost } from '@/app/api/v1/admin/webscan/findings/route';
import { DELETE as jobCancel, GET as jobGet } from '@/app/api/v1/admin/webscan/jobs/[id]/route';
import { POST as jobCreate } from '@/app/api/v1/admin/webscan/jobs/route';
import { PUT as settingsPut } from '@/app/api/v1/admin/webscan/settings/route';
import { DELETE as targetDelete, GET as targetGet } from '@/app/api/v1/admin/webscan/targets/[id]/route';
import { POST as targetCreate } from '@/app/api/v1/admin/webscan/targets/route';
import { POST as artifactsPost } from '@/app/api/v1/webscan/jobs/[id]/artifacts/route';
import { POST as heartbeatPost } from '@/app/api/v1/webscan/jobs/[id]/heartbeat/route';
import { POST as resultsPost } from '@/app/api/v1/webscan/jobs/[id]/results/route';
import { POST as claimPost } from '@/app/api/v1/webscan/jobs/claim/route';
import { webscanJobs, webTargets } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { createApiToken } from '@/lib/auth/tokens';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { JobSpec } from '@/lib/webscan/contract';
import { expireStaleJobs } from '@/lib/webscan/jobs';
import { setSelfIpsForTests, setWebscanLookupForTests } from '@/lib/webscan/scope';
import { urgentWebFindings } from '@/lib/webscan/view';
import { HTTPX_OUT, NUCLEI_OUT, TESTSSL_OUT, TLSX_OUT } from '../fixtures/webscan';
import { createTestDb } from '../helpers/db';

const ENV_TOKEN = 'compose-webscan-token-0123456789abcdef';
// lifecycle 的目標是 plain.example.com：憑證名稱也要對上，否則多一筆「名稱不符」
const TLSX_PLAIN = TLSX_OUT.replaceAll('shop.example.com', 'plain.example.com');
const CAPS = ['httpx', 'tlsx', 'nuclei', 'testssl'].map((scanner) => ({ scanner, version: '1.0.0' }));

let db: DB;
let runnerToken: string;
let readToken: string;
const dns: Record<string, string[]> = {};

function req(url: string, init: { method?: string; token?: string; body?: unknown; raw?: string | Buffer; headers?: Record<string, string> } = {}) {
  return new Request(`http://localhost:3000${url}`, {
    method: init.method ?? 'GET',
    headers: {
      'content-type': init.raw !== undefined ? 'application/octet-stream' : 'application/json',
      ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
      ...(init.headers ?? {}),
    },
    body: init.raw !== undefined ? (typeof init.raw === 'string' ? init.raw : new Uint8Array(init.raw)) : init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}
const params = (id: string) => ({ params: Promise.resolve({ id }) });
const admin = { token: 'test-admin' };

async function addTarget(url: string) {
  const r = await targetCreate(req('/api/v1/admin/webscan/targets', { method: 'POST', ...admin, body: { url } }));
  return { status: r.status, body: await r.json() };
}
async function newJob(target_id: string, profile = 'passive') {
  const r = await jobCreate(req('/api/v1/admin/webscan/jobs', { method: 'POST', ...admin, body: { target_id, profile } }));
  return { status: r.status, body: await r.json() };
}
async function claim(token = runnerToken, extra: Record<string, unknown> = {}) {
  const r = await claimPost(req('/api/v1/webscan/jobs/claim', { method: 'POST', token, body: { version: '0.9.0', hostname: 'webscan-01', capabilities: CAPS, max_jobs: 2, self_ips: ['172.20.0.5'], ...extra } }));
  return { status: r.status, body: await r.json() };
}
async function upload(jobId: string, scanner: string, text: string, format = 'jsonl', gzip = false) {
  const body = gzip ? zlib.gzipSync(Buffer.from(text)) : text;
  return artifactsPost(
    req(`/api/v1/webscan/jobs/${jobId}/artifacts?scanner=${scanner}&format=${format}&exit_code=0&duration_ms=12&truncated=0`, { method: 'POST', token: runnerToken, raw: body, headers: gzip ? { 'content-encoding': 'gzip' } : {} }),
    params(jobId),
  );
}
async function finish(jobId: string, steps: { scanner: string; ok: boolean }[], extra: Record<string, unknown> = {}) {
  const r = await resultsPost(
    req(`/api/v1/webscan/jobs/${jobId}/results`, { method: 'POST', token: runnerToken, body: { ok: steps.every((s) => s.ok), error: null, steps: steps.map((s) => ({ ...s, exit_code: 0, duration_ms: 10, error: null })), verify: null, ...extra } }),
    params(jobId),
  );
  return { status: r.status, body: await r.json() };
}

beforeAll(async () => {
  db = await createTestDb();
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  resetEnvForTests();
  runnerToken = (await createApiToken({ name: 'webscan-01', scopes: ['webscan'], actor: 'test' })).token;
  readToken = (await createApiToken({ name: 'grafana', scopes: ['read', 'dns'], actor: 'test' })).token;
  setSelfIpsForTests([]);
  setWebscanLookupForTests(async (h) => {
    if (!dns[h]) throw new Error('ENOTFOUND');
    return dns[h];
  });
  Object.assign(dns, {
    'shop.example.com': ['93.184.216.34'],
    'plain.example.com': ['93.184.216.35'],
    'rebind.example.net': ['93.184.216.36', '127.0.0.1'],
    'meta.example.net': ['169.254.169.254'],
    'intranet.corp': ['192.168.50.20'],
    'other-lan.corp': ['10.9.9.9'],
  });
});

afterAll(() => {
  setWebscanLookupForTests(null);
  setSelfIpsForTests(null);
});

beforeEach(() => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  delete process.env.AI_SECURITY_MONITOR_HUB_WEBSCAN_TOKEN;
  resetEnvForTests();
  resetRateLimitsForTests();
});

describe('webscan: targets and scope', () => {
  it('adds a public target without an ownership challenge and refuses duplicates and junk', async () => {
    const r = await addTarget('Shop.Example.com');
    expect(r.status).toBe(200);
    expect(r.body.target).toMatchObject({ url: 'https://shop.example.com/', host: 'shop.example.com' });
    expect(r.body.target).not.toHaveProperty('verifyToken');
    expect(r.body.screen).toEqual({ ok: true, ips: ['93.184.216.34'], internal: false });
    expect((await addTarget('https://shop.example.com/')).status).toBe(409);
    expect((await addTarget('ftp://shop.example.com')).body.error).toBe('bad_scheme');
    expect((await addTarget('http://localhost:3000/')).body.error).toBe('forbidden_host');
  });

  it('blocks scans whose host resolves to loopback, metadata or private ranges outside the allowlist', async () => {
    for (const [host, reason] of [
      ['rebind.example.net', 'loopback'],
      ['meta.example.net', 'metadata'],
      ['other-lan.corp', 'private_not_allowed'],
    ] as const) {
      const t = await addTarget(`https://${host}/`);
      expect(t.status).toBe(200);
      const j = await newJob(t.body.target.id);
      expect(j.status).toBe(422);
      expect(j.body.error).toBe(`blocked_target:${reason}`);
    }
    // 直接給 IP 也一樣
    const ip = await addTarget('http://127.0.0.1:8080/');
    expect((await newJob(ip.body.target.id)).body.error).toBe('blocked_target:loopback');
  });

  it('internal targets need the allowlist; once listed they count as authorized for active scans', async () => {
    const t = await addTarget('http://intranet.corp/');
    expect(t.body.screen).toMatchObject({ ok: false, reason: 'private_not_allowed' });
    expect((await newJob(t.body.target.id)).body.error).toBe('blocked_target:private_not_allowed');
    const s = await settingsPut(req('/api/v1/admin/webscan/settings', { method: 'PUT', ...admin, body: { internal_cidrs: ['192.168.50.20'] } }));
    expect((await s.json()).settings.internal_cidrs).toEqual(['192.168.50.20/32']);
    const bad = await settingsPut(req('/api/v1/admin/webscan/settings', { method: 'PUT', ...admin, body: { internal_cidrs: ['0.0.0.0/0'] } }));
    expect(bad.status).toBe(400);
    const j = await newJob(t.body.target.id, 'active_light');
    expect(j.status).toBe(200);
    expect(j.body.job).toMatchObject({ profile: 'active_light', internal: true, pinnedIps: ['192.168.50.20'], scanners: ['httpx', 'nuclei'] });
    await jobCancel(req(`/api/v1/admin/webscan/jobs/${j.body.job.id}`, { method: 'DELETE', ...admin }), params(j.body.job.id));
  });

});

describe('webscan: runner lifecycle', () => {
  it('only webscan tokens can claim; the compose env token works too', async () => {
    expect((await claim(readToken)).status).toBe(401);
    expect((await claim('nope')).status).toBe(401);
    process.env.AI_SECURITY_MONITOR_HUB_WEBSCAN_TOKEN = ENV_TOKEN;
    resetEnvForTests();
    const r = await claim(ENV_TOKEN);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ jobs: [], poll_after_ms: 15000 });
    const view = await (await overview(req('/api/v1/admin/webscan', admin))).json();
    expect(view.runners.find((x: { id: string }) => x.id === 'env')).toMatchObject({ online: true, hostname: 'webscan-01' });
  });

  it('passive scan: claim → heartbeat → artifacts → results → findings, then a rescan resolves what disappeared', async () => {
    const target = (await (await targetCreate(req('/api/v1/admin/webscan/targets', { method: 'POST', ...admin, body: { url: 'https://plain.example.com/' } }))).json()).target;
    const created = await newJob(target.id);
    expect(created.status).toBe(200);
    expect(created.body.job.scanners).toEqual(['httpx', 'tlsx']);
    expect((await newJob(target.id)).status).toBe(409);

    const c = await claim();
    expect(c.status).toBe(200);
    expect(c.body.jobs).toHaveLength(1);
    const spec = c.body.jobs[0];
    expect(JobSpec.safeParse(spec).success).toBe(true);
    expect(spec).toMatchObject({ kind: 'scan', profile: 'passive', target: { host: 'plain.example.com', pinned_ips: ['93.184.216.35'], internal: false }, scope: { hosts: ['plain.example.com'], allowed_private_cidrs: [] } });
    expect(spec.steps.map((s: { scanner: string }) => s.scanner)).toEqual(['httpx', 'tlsx']);
    // 同一份工作不會再給第二次
    expect((await claim()).body.jobs).toHaveLength(0);

    const hb = await heartbeatPost(req(`/api/v1/webscan/jobs/${spec.id}/heartbeat`, { method: 'POST', token: runnerToken, body: { step: 'httpx', progress: 0.5 } }), params(spec.id));
    expect(hb.status).toBe(200);
    expect(await hb.json()).toMatchObject({ ok: true, cancel: false });

    expect((await upload(spec.id, 'httpx', HTTPX_OUT)).status).toBe(200);
    expect((await upload(spec.id, 'tlsx', TLSX_PLAIN, 'jsonl', true)).status).toBe(200);
    // 不在這份工作裡的掃描器拒收
    expect((await upload(spec.id, 'nuclei', NUCLEI_OUT)).status).toBe(400);

    const done = await finish(spec.id, [{ scanner: 'httpx', ok: true }, { scanner: 'tlsx', ok: true }]);
    expect(done.status).toBe(200);
    expect(done.body).toMatchObject({ status: 'succeeded', findings: { new: 3, resolved: 0, open: 3 } });

    const detail = await (await targetGet(req(`/api/v1/admin/webscan/targets/${target.id}`, admin), params(target.id))).json();
    expect(detail.target.fingerprint).toMatchObject({ webserver: 'nginx', tech: ['Nginx', 'PHP'] });
    expect(detail.findings.map((f: { rule: string }) => f.rule).sort()).toEqual(['tls.cert_expiring', 'tls.cert_self_signed', 'tls.old_protocol']);
    expect(detail.latest.artifacts.map((a: { scanner: string }) => a.scanner)).toEqual(['httpx', 'tlsx']);

    // 原始輸出可下載（附件、不給瀏覽器猜型別）
    const art = await artifactGet(req(`/api/v1/admin/webscan/artifacts/${detail.latest.artifacts[1].id}`, admin), params(String(detail.latest.artifacts[1].id)));
    expect(art.headers.get('content-disposition')).toMatch(/attachment/);
    expect(art.headers.get('x-content-type-options')).toBe('nosniff');
    expect(await art.text()).toBe(TLSX_PLAIN);

    // 已讀其中一個
    const ack = await findingsPost(req('/api/v1/admin/webscan/findings', { method: 'POST', ...admin, body: { action: 'ack', target_id: target.id, ids: [detail.findings[0].findingId] } }));
    expect((await ack.json()).updated).toBe(1);

    // 第二次：憑證問題修好了（tlsx 沒命中）→ 三個都變已解決
    const j2 = (await newJob(target.id)).body.job;
    const c2 = await claim();
    expect(c2.body.jobs[0].id).toBe(j2.id);
    await upload(j2.id, 'httpx', HTTPX_OUT);
    await upload(j2.id, 'tlsx', JSON.stringify({ host: 'plain.example.com', probe_status: true, tls_version: 'tls13', not_after: '2027-06-01T00:00:00Z' }));
    const d2 = await finish(j2.id, [{ scanner: 'httpx', ok: true }, { scanner: 'tlsx', ok: true }]);
    expect(d2.body.findings).toMatchObject({ new: 0, resolved: 3, open: 0 });

    // 第三次：tlsx 這一步失敗 → 不能拿來判斷「已解決」，之前的狀態不動；又出現的會重新開啟
    const j3 = (await newJob(target.id)).body.job;
    await claim();
    await upload(j3.id, 'tlsx', TLSX_PLAIN);
    const d3 = await finish(j3.id, [{ scanner: 'httpx', ok: false }, { scanner: 'tlsx', ok: true }]);
    expect(d3.body).toMatchObject({ status: 'failed', findings: { reopened: 3, open: 3 } });
  });

  it('manual active scans run without ownership verification', async () => {
    const t = (await addTarget('https://shop.example.com/app')).body.target;
    const j2 = await newJob(t.id, 'active_light');
    expect(j2.status).toBe(200);
    expect(j2.body.job.scanners).toEqual(['httpx', 'tlsx', 'nuclei', 'testssl']);
    const c = await claim();
    const spec = c.body.jobs.find((x: { id: string }) => x.id === j2.body.job.id);
    expect(spec.steps.find((s: { scanner: string }) => s.scanner === 'nuclei').options.exclude_tags).toContain('dos');
    await upload(spec.id, 'nuclei', NUCLEI_OUT);
    await upload(spec.id, 'testssl', TESTSSL_OUT, 'json');
    const done = await finish(spec.id, [{ scanner: 'nuclei', ok: true }, { scanner: 'testssl', ok: true }]);
    expect(done.body.findings.new).toBe(5);
  });

  it('retires legacy verification jobs without sending them to runners', async () => {
    const t = (await addTarget('https://shop.example.com/legacy')).body.target;
    const j = (await newJob(t.id)).body.job;
    await db.update(webscanJobs).set({ kind: 'verify', scanners: [] }).where(eq(webscanJobs.id, j.id));
    expect((await claim()).body.jobs.map((x: { id: string }) => x.id)).not.toContain(j.id);
    expect((await db.select().from(webscanJobs).where(eq(webscanJobs.id, j.id)))[0]).toMatchObject({ status: 'cancelled', error: 'verification_removed' });
  });

  it('cancel: pending ends at once; running gets cancel on the next heartbeat; strangers get 409', async () => {
    const t = (await addTarget('https://shop.example.com/cancel')).body.target;
    const j = (await newJob(t.id)).body.job;
    const c = await claim();
    expect(c.body.jobs.map((x: { id: string }) => x.id)).toContain(j.id);
    await jobCancel(req(`/api/v1/admin/webscan/jobs/${j.id}`, { method: 'DELETE', ...admin }), params(j.id));
    const hb = await heartbeatPost(req(`/api/v1/webscan/jobs/${j.id}/heartbeat`, { method: 'POST', token: runnerToken, body: {} }), params(j.id));
    expect(await hb.json()).toMatchObject({ cancel: true });
    const other = (await createApiToken({ name: 'webscan-02', scopes: ['webscan'], actor: 'test' })).token;
    expect((await heartbeatPost(req(`/api/v1/webscan/jobs/${j.id}/heartbeat`, { method: 'POST', token: other, body: {} }), params(j.id))).status).toBe(409);
    expect((await finish(j.id, [])).body.status).toBe('cancelled');
    const d = await (await jobGet(req(`/api/v1/admin/webscan/jobs/${j.id}`, admin), params(j.id))).json();
    expect(d.job.status).toBe('cancelled');
  });

  it('expired leases go back to the queue (then fail after 3 attempts); runner self addresses are refused', async () => {
    const t = (await addTarget('https://shop.example.com/lease')).body.target;
    const j = (await newJob(t.id)).body.job;
    for (let i = 1; i <= 3; i++) {
      const c = await claim();
      expect(c.body.jobs.map((x: { id: string }) => x.id)).toContain(j.id);
      await db.update(webscanJobs).set({ leaseExpiresAt: new Date(Date.now() - 1000) }).where(eq(webscanJobs.id, j.id));
      await expireStaleJobs(db);
    }
    const row = (await db.select().from(webscanJobs).where(eq(webscanJobs.id, j.id)))[0]!;
    expect(row).toMatchObject({ status: 'failed', error: 'lease_expired', attempts: 3 });

    const t2 = (await addTarget('https://shop.example.com/self')).body.target;
    const j2 = (await newJob(t2.id)).body.job;
    const c2 = await claim(runnerToken, { self_ips: ['93.184.216.34'] });
    expect(c2.body.jobs.map((x: { id: string }) => x.id)).not.toContain(j2.id);
    expect((await db.select().from(webscanJobs).where(eq(webscanJobs.id, j2.id)))[0]!.error).toBe('blocked_target:self');
  });

  it('findings of a deleted target no longer count towards the sidebar badge', async () => {
    const t = (await addTarget('https://shop.example.com/badge')).body.target;
    const j = (await newJob(t.id)).body.job;
    await claim();
    await upload(j.id, 'tlsx', TLSX_OUT);
    await finish(j.id, [{ scanner: 'tlsx', ok: true }]);
    const before = await urgentWebFindings(db);
    await targetDelete(req(`/api/v1/admin/webscan/targets/${t.id}`, { method: 'DELETE', ...admin }), params(t.id));
    expect(await urgentWebFindings(db)).toBe(before - 1);
  });

  it('a runner without the right scanners does not get the job; deleting a target cancels its jobs', async () => {
    const t = (await addTarget('https://shop.example.com/caps')).body.target;
    const j = (await newJob(t.id)).body.job;
    const c = await claim(runnerToken, { capabilities: [{ scanner: 'httpx', version: '1' }] });
    expect(c.body.jobs.map((x: { id: string }) => x.id)).not.toContain(j.id);
    const del = await targetDelete(req(`/api/v1/admin/webscan/targets/${t.id}`, { method: 'DELETE', ...admin }), params(t.id));
    expect(del.status).toBe(200);
    expect((await db.select().from(webscanJobs).where(eq(webscanJobs.id, j.id)))[0]!.status).toBe('cancelled');
  });
});
