import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { POST as syncRoute } from '@/app/api/v1/admin/feeds/sync/route';
import { GET as usageGet, PUT as usagePut } from '@/app/api/v1/admin/intel-usage/route';
import { POST as heartbeat } from '@/app/api/v1/agents/me/heartbeat/route';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { GET as feedRoute } from '@/app/api/v1/feeds/[id]/route';
import { GET as manifestRoute } from '@/app/api/v1/feeds/manifest/route';
import { agents, auditLog } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { resetRateLimitsForTests } from '@/lib/auth/ratelimit';
import { resetThrottleForTests } from '@/lib/ingest/route';
import { expandUrls, readMeta, refreshMs, resetMirrorStateForTests, syncFeeds } from '@/lib/intel/mirror';
import { shouldRefresh } from '@/lib/intel/sync-state';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const AGENT_ID = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asa-feeds-'));
const FEEDS = path.join(tmp, 'feeds');
const CACHE = path.join(tmp, 'cache');

const registry = {
  feeds: [
    { id: 'test-plain', name: 'Plain', vendor: 'Test', urls: ['https://feeds.example/plain.txt'], format: 'plain-ip-per-line', kind: 'ip', direction: 'both', confidence: 90, license: { name: 'CC0', url: 'https://example/cc0', attribution_required: false, commercial_ok: true }, refresh_interval: '1h', requires_api_key: null, enabled_default: true, tags: [] },
    { id: 'test-off', name: 'Off', vendor: 'Test', urls: ['https://feeds.example/off.txt'], format: 'plain-ip-per-line', kind: 'ip', direction: 'both', confidence: 50, license: { name: 'CC0', url: 'https://example/cc0', attribution_required: false, commercial_ok: true }, refresh_interval: '1h', requires_api_key: null, enabled_default: false, tags: [] },
    { id: 'test-nc', name: 'NonCommercial', vendor: 'Test', urls: ['https://feeds.example/nc.txt'], format: 'plain-ip-per-line', kind: 'ip', direction: 'both', confidence: 80, license: { name: 'CC BY-NC', url: 'https://example/nc', attribution_required: true, commercial_ok: false }, refresh_interval: '1h', requires_api_key: null, enabled_default: true, tags: [] },
    { id: 'test-lookup', name: 'Lookup', vendor: 'Test', urls: ['https://api.example/{ip}'], format: 'lookup-api', kind: 'lookup', direction: 'both', confidence: 50, license: { name: 'x', url: 'https://example', attribution_required: false, commercial_ok: false }, refresh_interval: '24h', requires_api_key: null, enabled_default: true, tags: [] },
  ],
};

let db: DB;
let calls: { url: string; headers: Record<string, string> }[] = [];
let body = '# header\n198.51.100.7\n203.0.113.9\n';

beforeAll(async () => {
  fs.mkdirSync(FEEDS, { recursive: true });
  fs.writeFileSync(path.join(FEEDS, 'registry.json'), JSON.stringify(registry));
  process.env.ASA_HUB_FEEDS_DIR = FEEDS;
  process.env.ASA_HUB_FEED_CACHE_DIR = CACHE;
  (globalThis as { __asaRegistry?: unknown }).__asaRegistry = undefined;
  db = await createTestDb();
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ url, headers });
    if (headers['if-none-match'] === '"v1"' && body.includes('198.51.100.7') && !body.includes('192.0.2.1')) return new Response(null, { status: 304 });
    return new Response(body, { status: 200, headers: { etag: '"v1"' } });
  });
});

afterAll(() => {
  vi.unstubAllGlobals();
  delete process.env.ASA_HUB_FEEDS_DIR;
  delete process.env.ASA_HUB_FEED_CACHE_DIR;
  (globalThis as { __asaRegistry?: unknown }).__asaRegistry = undefined;
  fs.rmSync(tmp, { recursive: true, force: true });
});

beforeEach(() => {
  process.env.ASA_HUB_INTEL_USAGE = 'commercial';
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_SNAPSHOT_MIN_INTERVAL_MS = '0';
  process.env.ASA_HUB_FEED_MIRROR = '0';
  resetEnvForTests();
  resetThrottleForTests();
  resetRateLimitsForTests();
  resetMirrorStateForTests();
});

const client = { authorization: 'Bearer client-a' };
const admin = { authorization: 'Bearer test-admin' };

describe('feed mirror', () => {
  it('helpers', () => {
    expect(refreshMs('30m')).toBe(1_800_000);
    expect(refreshMs('720h')).toBe(720 * 3_600_000);
    expect(refreshMs('bogus')).toBe(3_600_000);
    expect(expandUrls('https://x/{YYYY}-{MM}.gz', new Date('2026-01-05T00:00:00Z'))).toEqual(['https://x/2026-01.gz', 'https://x/2025-12.gz']);
    expect(shouldRefresh(null, null)).toBe(false);
    expect(shouldRefresh(new Date(), null)).toBe(true);
    expect(shouldRefresh(new Date(Date.now() - 1000), new Date())).toBe(false);
    expect(shouldRefresh(new Date(Date.now() - 25 * 3_600_000), null)).toBe(false);
  });

  it('syncs enabled downloadable feeds only, keeps headers, honors freshness and 304', async () => {
    calls = [];
    const first = await syncFeeds();
    expect(first).toEqual([expect.objectContaining({ feed_id: 'test-plain', status: 'updated' })]);
    expect(calls.map((c) => c.url)).toEqual(['https://feeds.example/plain.txt']);
    const m = readMeta('test-plain');
    expect(m).toMatchObject({ status: 'ok', entries: 2, etag: '"v1"' });
    expect(fs.readFileSync(path.join(CACHE, 'test-plain', 'latest'), 'utf8')).toContain('# header');

    calls = [];
    expect((await syncFeeds())[0].status).toBe('fresh');
    expect(calls).toHaveLength(0);
    expect((await syncFeeds({ force: true }))[0].status).toBe('not_modified');
    expect(calls[0].headers['if-none-match']).toBe('"v1"');
  });

  it('keeps old data when the vendor returns an empty list', async () => {
    const before = readMeta('test-plain')!.sha256;
    body = '# nothing today\n';
    const r = await syncFeeds({ force: true });
    expect(r[0]).toMatchObject({ status: 'error' });
    expect(readMeta('test-plain')).toMatchObject({ status: 'error', sha256: before });
    body = '# header\n198.51.100.7\n203.0.113.9\n';
  });

  it('serves manifest and raw feed to agents with ETag; viewers cannot', async () => {
    await syncFeeds({ force: true });
    expect((await manifestRoute(req('/api/v1/feeds/manifest'))).status).toBe(401);
    const man = await manifestRoute(req('/api/v1/feeds/manifest', { headers: client }));
    expect(man.status).toBe(200);
    const j = (await man.json()) as { feeds: { id: string; sha256: string }[] };
    expect(j.feeds.map((f) => f.id)).toEqual(['test-plain']);
    const sha = j.feeds[0].sha256;

    const params = { params: Promise.resolve({ id: 'test-plain' }) };
    const raw = await feedRoute(req('/api/v1/feeds/test-plain', { headers: client }), params);
    expect(raw.status).toBe(200);
    expect(raw.headers.get('etag')).toBe(`"${sha}"`);
    expect(raw.headers.get('x-asa-feed-license')).toContain('CC0');
    expect(await raw.text()).toContain('198.51.100.7');
    const same = await feedRoute(req('/api/v1/feeds/test-plain', { headers: { ...client, 'if-none-match': `"${sha}"` } }), params);
    expect(same.status).toBe(304);
    expect((await feedRoute(req('/api/v1/feeds/test-off', { headers: client }), { params: Promise.resolve({ id: 'test-off' }) })).status).toBe(404);
    expect((await feedRoute(req('/api/v1/feeds/../etc', { headers: client }), { params: Promise.resolve({ id: '../etc' }) })).status).toBe(404);
  });

  it('admin sync asks agents to refresh until they report a newer check', async () => {
    const reg = JSON.parse(fs.readFileSync(path.join(CONTRACT, 'register.v1.json'), 'utf8'));
    await register(new Request('http://localhost:3000/api/v1/agents/register', { method: 'POST', headers: { ...client, 'content-type': 'application/json' }, body: JSON.stringify(reg) }));
    const hb = (extra: Record<string, unknown> = {}) =>
      heartbeat(
        new Request('http://localhost:3000/api/v1/agents/me/heartbeat', {
          method: 'POST',
          headers: { ...client, 'content-type': 'application/json' },
          body: JSON.stringify({ agent_id: AGENT_ID, ts: new Date().toISOString(), version: '0.1.1', ...extra }),
        }),
      );
    expect(((await (await hb()).json()) as { commands: string[] }).commands).toEqual([]);

    expect((await syncRoute(req('/api/v1/admin/feeds/sync', { method: 'POST', body: {}, headers: client }))).status).toBe(401);
    const s = await syncRoute(req('/api/v1/admin/feeds/sync', { method: 'POST', body: {}, headers: admin }));
    expect(s.status).toBe(200);
    const all = ((await s.json()) as { outcomes: { feed_id: string }[] }).outcomes;
    expect(all).toHaveLength(1);
    // 只更新指定的來源（每一列的「立即更新」）；不存在的 id 不會更新任何東西，格式不對回 400
    const sync = (body: unknown) => syncRoute(req('/api/v1/admin/feeds/sync', { method: 'POST', body, headers: admin }));
    const one = await sync({ only: [all[0].feed_id], refresh_agents: false });
    expect(((await one.json()) as { outcomes: { feed_id: string }[] }).outcomes.map((o) => o.feed_id)).toEqual([all[0].feed_id]);
    expect(((await (await sync({ only: ['no-such-feed'], refresh_agents: false })).json()) as { outcomes: unknown[] }).outcomes).toEqual([]);
    expect((await sync({ only: ['../etc/passwd'] })).status).toBe(400);

    expect(((await (await hb({ intel_checked_at: '2026-01-01T00:00:00Z' })).json()) as { commands: string[] }).commands).toEqual(['refresh_feeds']);
    const fresh = await hb({ intel_checked_at: new Date(Date.now() + 1000).toISOString(), intel_feeds: { ok: 17, total: 18, source: 'hub' } });
    expect(((await fresh.json()) as { commands: string[] }).commands).toEqual([]);
    const [row] = await db.select().from(agents).where(eq(agents.id, AGENT_ID));
    expect(row.intelFeeds).toEqual({ ok: 17, total: 18, source: 'hub' });
    expect(row.intelCheckedAt).toBeInstanceOf(Date);
  });

  it('mirrors noncommercial-only feeds only when the Hub is set to noncommercial use', async () => {
    const put = (usage: unknown, headers = admin) => usagePut(req('/api/v1/admin/intel-usage', { method: 'PUT', body: { usage }, headers }));
    delete process.env.ASA_HUB_INTEL_USAGE;
    resetEnvForTests();
    // 沒設定：預設個人／非商業用途
    expect(await (await usageGet(req('/api/v1/admin/intel-usage', { headers: admin }))).json()).toEqual({ usage: 'noncommercial', source: 'default' });
    expect((await put('commercial')).status).toBe(200);
    // 商用：不同步、不給主機
    expect((await syncFeeds({ force: true })).map((o) => o.feed_id)).not.toContain('test-nc');
    expect((await feedRoute(req('/api/v1/feeds/test-nc', { headers: client }), { params: Promise.resolve({ id: 'test-nc' }) })).status).toBe(404);

    expect((await put('noncommercial', client)).status).toBe(401);
    expect((await put('bogus')).status).toBe(400);
    const r = await put('noncommercial');
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ usage: 'noncommercial', source: 'settings' });
    const updates = await db.select().from(auditLog).where(eq(auditLog.action, 'intel_usage.updated'));
    expect(updates.map((u) => u.details)).toEqual([
      expect.objectContaining({ before: 'noncommercial', after: 'commercial' }),
      expect.objectContaining({ before: 'commercial', after: 'noncommercial' }),
    ]);

    resetMirrorStateForTests();
    expect((await syncFeeds({ force: true })).map((o) => o.feed_id)).toContain('test-nc');
    const man = (await (await manifestRoute(req('/api/v1/feeds/manifest', { headers: client }))).json()) as { feeds: { id: string }[] };
    expect(man.feeds.map((x) => x.id)).toContain('test-nc');
    expect((await feedRoute(req('/api/v1/feeds/test-nc', { headers: client }), { params: Promise.resolve({ id: 'test-nc' }) })).status).toBe(200);

    // 環境變數鎖定：網頁上不能改
    process.env.ASA_HUB_INTEL_USAGE = 'commercial';
    resetEnvForTests();
    expect(await (await usageGet(req('/api/v1/admin/intel-usage', { headers: admin }))).json()).toEqual({ usage: 'commercial', source: 'env' });
    expect((await put('noncommercial')).status).toBe(409);
    delete process.env.ASA_HUB_INTEL_USAGE;
    resetEnvForTests();
    await put('commercial');
  });
});
