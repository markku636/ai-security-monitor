import { eq } from 'drizzle-orm';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { GET as cfgGet, POST as cfgPost } from '@/app/api/v1/admin/ip-intel/route';
import { GET as intelGet, POST as intelPost } from '@/app/api/v1/ip-intel/route';
import { auditLog, ipReputation, settings } from '@/drizzle/schema';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import type { IpIntelView, SourcesConfigStatus } from '@/lib/ipintel/types';
import { createTestDb } from '../helpers/db';

const req = (url: string, init: RequestInit & { token?: string | null } = {}) =>
  new Request(`http://localhost:3000${url}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      host: 'localhost:3000',
      ...(init.token === null ? {} : { authorization: `Bearer ${init.token ?? 'test-admin'}` }),
    },
  });

const IP = '45.155.205.233';

function fakeFetch() {
  const calls: string[] = [];
  const f = vi.fn(async (url: string | URL | Request) => {
    const u = String(url);
    calls.push(u);
    if (u.startsWith('https://api.abuseipdb.com/')) {
      return Response.json({ data: { ipAddress: IP, abuseConfidenceScore: 100, totalReports: 812, countryCode: 'RU', usageType: 'Data Center/Web Hosting/Transit', isp: 'Bad Host', isTor: false } });
    }
    if (u.startsWith('https://api.greynoise.io/')) return Response.json({ ip: IP, classification: 'malicious', noise: true, riot: false, name: 'unknown' });
    if (u.startsWith('https://proxycheck.io/')) return Response.json({ status: 'ok', [IP]: { proxy: 'no', type: 'Business', risk: 33, isocode: 'RU' } });
    return new Response('not found', { status: 404 });
  });
  return { f, calls };
}

let db: DB;

beforeAll(async () => {
  db = await createTestDb();
});

beforeEach(async () => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  delete process.env.ASA_HUB_IP_LOOKUPS;
  delete process.env.ASA_HUB_ABUSEIPDB_KEY;
  resetEnvForTests();
  resetRateLimitsForTests();
  await db.delete(ipReputation);
  await db.delete(settings);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('ip-intel', () => {
  it('stores keys write-only and never returns them', async () => {
    const r = await cfgPost(req('/api/v1/admin/ip-intel', { method: 'POST', body: JSON.stringify({ keys: { abuseipdb: 'abcdef1234567890' }, disabled: ['rdns'] }) }));
    expect(r.status).toBe(200);
    const s = (await r.json()) as SourcesConfigStatus;
    const ab = s.providers.find((p) => p.id === 'abuseipdb')!;
    expect(ab).toMatchObject({ keySource: 'settings', keyHint: 'abc••••890' });
    expect(JSON.stringify(s)).not.toContain('abcdef1234567890');
    expect(s.providers.find((p) => p.id === 'rdns')!.enabled).toBe(false);
    const [a] = await db.select().from(auditLog).where(eq(auditLog.action, 'ip_intel.config'));
    expect(JSON.stringify(a.details)).not.toContain('abcdef1234567890');
    // 環境變數優先
    process.env.ASA_HUB_ABUSEIPDB_KEY = 'from-env-key-0000';
    const g = (await (await cfgGet(req('/api/v1/admin/ip-intel'))).json()) as SourcesConfigStatus;
    expect(g.providers.find((p) => p.id === 'abuseipdb')!.keySource).toBe('env');
    // 只有 admin
    expect((await cfgGet(req('/api/v1/admin/ip-intel', { token: null }))).status).toBe(401);
  });

  it('GET only reads the cache; POST queries the enabled sources and caches the result', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    await cfgPost(req('/api/v1/admin/ip-intel', { method: 'POST', body: JSON.stringify({ keys: { abuseipdb: 'k-abuse-123456' }, disabled: ['rdns'] }) }));

    const before = (await (await intelGet(req(`/api/v1/ip-intel?ip=${IP}`))).json()) as IpIntelView;
    expect(before.score).toBeNull();
    expect(before.providers.filter((p) => p.willQuery).map((p) => p.id)).toEqual(['abuseipdb', 'greynoise', 'proxycheck']);
    expect(calls).toHaveLength(0);

    const r = await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: IP }) }));
    expect(r.status).toBe(200);
    const v = (await r.json()) as IpIntelView & { queried: string[] };
    expect(v.queried.sort()).toEqual(['abuseipdb', 'greynoise', 'proxycheck']);
    expect(calls.find((u) => u.includes('abuseipdb'))).toContain(`ipAddress=${IP}`);
    expect(v.score).toMatchObject({ score: 75, level: 'critical' });
    expect(v.profile).toMatchObject({ abuseScore: 100, abuseReports: 812, greynoiseClass: 'malicious', isDatacenter: true, proxyRisk: 33 });
    expect(v.providers.find((p) => p.id === 'abuseipdb')!.hit).toBe(true);
    expect(v.providers.find((p) => p.id === 'proxycheck')!.hit).toBe(false);
    expect(v.providers.find((p) => p.id === 'ipinfo')!.result).toBeNull();

    // 快取內不重打；refresh 才重打
    await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: IP }) }));
    expect(calls).toHaveLength(3);
    await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: IP, refresh: true }) }));
    expect(calls).toHaveLength(6);

    const cached = (await (await intelGet(req(`/api/v1/ip-intel?ip=${IP}`))).json()) as IpIntelView;
    expect(cached.score?.score).toBe(75);
    const audits = await db.select().from(auditLog).where(eq(auditLog.action, 'ip_intel.lookup'));
    expect(audits).toHaveLength(2);
  });

  it('never sends private addresses out, honours the kill switch and requires admin', async () => {
    const { f, calls } = fakeFetch();
    vi.stubGlobal('fetch', f);
    expect((await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: '192.168.50.49' }) }))).status).toBe(400);
    expect((await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: 'nope' }) }))).status).toBe(400);
    process.env.ASA_HUB_IP_LOOKUPS = 'off';
    expect((await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: IP }) }))).status).toBe(409);
    delete process.env.ASA_HUB_IP_LOOKUPS;
    expect((await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: IP }), token: null }))).status).toBe(401);
    expect(calls).toHaveLength(0);
  });

  it('a failed refresh keeps the last good data', async () => {
    const { f } = fakeFetch();
    vi.stubGlobal('fetch', f);
    await cfgPost(req('/api/v1/admin/ip-intel', { method: 'POST', body: JSON.stringify({ disabled: ['rdns', 'proxycheck'] }) }));
    await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: IP }) }));
    vi.stubGlobal('fetch', vi.fn(async () => new Response('busy', { status: 503 })));
    const v = (await (await intelPost(req('/api/v1/ip-intel', { method: 'POST', body: JSON.stringify({ ip: IP, refresh: true }) }))).json()) as IpIntelView;
    const gn = v.providers.find((p) => p.id === 'greynoise')!;
    expect(gn.result).toMatchObject({ ok: true, detail: 'http-error: HTTP 503' });
    expect(v.profile.greynoiseClass).toBe('malicious');
  });
});
