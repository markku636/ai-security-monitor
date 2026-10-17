import path from 'node:path';
import { eq } from 'drizzle-orm';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GET as providersRoute } from '@/app/api/ai/providers/route';
import { POST as streamRoute } from '@/app/api/ai/stream/route';
import { aiAnalyses } from '@/drizzle/schema';
import { claudeEvents, codexEvents, stripMcpPrefix } from '@/lib/ai/events';
import { childEnv, claudeArgs, codexArgs, isRunToken, resolveBin } from '@/lib/ai/run';
import type { DB } from '@/lib/db';
import { resetEnvForTests } from '@/lib/env';
import { createTestDb } from '../helpers/db';
import { req } from '../helpers/req';

const FAKE = path.resolve(__dirname, '../fixtures/fake-claude.mjs');
const admin = { authorization: 'Bearer test-admin' };
let db: DB;

beforeAll(async () => {
  db = await createTestDb();
});

beforeEach(() => {
  process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
  process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
  process.env.ASA_HUB_DATABASE_URL = 'postgres://should-not-leak';
  process.env.ASA_HUB_CLAUDE_BIN = FAKE;
  process.env.ASA_HUB_CODEX_BIN = path.resolve(__dirname, 'does-not-exist');
  resetEnvForTests();
});

describe('ai event parsing and args', () => {
  it('maps claude and codex streams', () => {
    const st = { streamed: false };
    expect(claudeEvents('{"type":"assistant","message":{"content":[{"type":"tool_use","name":"mcp__asahub__list_findings","input":{"severity":["critical"]}}]}}', st)).toEqual([
      { type: 'tool', name: 'list_findings', input: '{"severity":["critical"]}' },
    ]);
    expect(claudeEvents('{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"嗨"}}}', st)).toEqual([{ type: 'text', text: '嗨' }]);
    expect(claudeEvents('{"type":"assistant","message":{"content":[{"type":"text","text":"dup"}]}}', st)).toEqual([]);
    expect(claudeEvents('not json', st)).toEqual([]);
    const cs: { lastText?: string } = {};
    expect(codexEvents('{"type":"item.completed","item":{"type":"agent_message","text":"答"}}', cs, 0)).toEqual([{ type: 'text', text: '答' }]);
    expect(codexEvents('{"type":"turn.completed"}', cs, 7)).toEqual([{ type: 'done', text: '答', is_error: false, duration_ms: 7 }]);
    expect(stripMcpPrefix('mcp__asahub__crash_history')).toBe('crash_history');
    expect(stripMcpPrefix('plain')).toBe('plain');
  });

  it('builds locked-down CLI args and a minimal env', () => {
    const spec = { provider: 'claude' as const, prompt: 'p', system: 'sys', maxTurns: 5, timeoutMs: 1000 };
    const a = claudeArgs(spec, '/tmp/mcp.json', true);
    expect(a).toContain('--strict-mcp-config');
    expect(a[a.indexOf('--permission-mode') + 1]).toBe('dontAsk');
    expect(a[a.indexOf('--allowedTools') + 1].split(',').every((x) => x.startsWith('mcp__asahub__'))).toBe(true);
    expect(claudeArgs(spec, 'x', false)).not.toContain('--append-system-prompt');
    const c = codexArgs({ ...spec, provider: 'codex' }, '/ws', 'http://127.0.0.1:3000/api/mcp');
    expect(c.join(' ')).toContain("mcp_servers.asahub.url='http://127.0.0.1:3000/api/mcp'");
    expect(c.join(' ')).toContain('--sandbox read-only');
    const env = childEnv({ X: '1' });
    expect(env.ASA_HUB_ADMIN_SECRET).toBeUndefined();
    expect(env.ASA_HUB_DATABASE_URL).toBeUndefined();
    expect(env.X).toBe('1');
    expect(isRunToken('nope')).toBe(false);
    expect(resolveBin('claude')?.prefix).toEqual([FAKE]);
    expect(resolveBin('codex')).toBeNull();
  });
});

describe('/api/ai', () => {
  it('lists providers for admins only', async () => {
    const r = await (await providersRoute(req('/api/ai/providers', { headers: admin }))).json();
    expect(r.providers).toEqual([
      { id: 'claude', available: true },
      { id: 'codex', available: false },
    ]);
    expect((await providersRoute(req('/api/ai/providers'))).status).toBe(401);
  });

  it('streams a run over SSE and records it', async () => {
    const res = await streamRoute(req('/api/ai/stream', { method: 'POST', headers: admin, body: { scope: 'fleet' } }));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    const text = await res.text();
    const events = text
      .split('\n\n')
      .filter((c) => c.startsWith('data: '))
      .map((c) => JSON.parse(c.slice(6)));
    expect(events[0]).toMatchObject({ type: 'start', provider: 'claude' });
    expect(events.find((e) => e.type === 'tool')).toMatchObject({ name: 'fleet_summary' });
    const answer = events.filter((e) => e.type === 'text').map((e) => e.text).join('');
    expect(answer).toContain('auth=true');
    expect(answer).toContain('type=http');
    expect(answer).toContain('leaked=0');
    expect(answer).toContain('strict=true');
    expect(answer).toMatch(/url=http:\/\/127\.0\.0\.1:\d+\/api\/mcp/);
    const end = events.at(-1);
    expect(end).toMatchObject({ type: 'end', status: 'done' });
    const row = (await db.select().from(aiAnalyses).where(eq(aiAnalyses.id, end.id)))[0];
    expect(row).toMatchObject({ status: 'done', provider: 'claude', scope: 'fleet', toolsCalled: 1 });
    expect(row.resultText).toContain('auth=true');
  });

  it('validates input and refuses unknown providers', async () => {
    expect((await streamRoute(req('/api/ai/stream', { method: 'POST', headers: admin, body: { scope: 'agent' } }))).status).toBe(400);
    expect((await streamRoute(req('/api/ai/stream', { method: 'POST', headers: admin, body: { scope: 'indicator' } }))).status).toBe(400);
    expect((await streamRoute(req('/api/ai/stream', { method: 'POST', headers: admin, body: { scope: 'indicator', indicator: 'evil.example; rm -rf' } }))).status).toBe(400);
    expect((await streamRoute(req('/api/ai/stream', { method: 'POST', headers: admin, body: { provider: 'codex' } }))).status).toBe(503);
    expect((await streamRoute(req('/api/ai/stream', { method: 'POST', body: {} }))).status).toBe(401);
  });

  it('kills the CLI when the client disconnects', async () => {
    const ac = new AbortController();
    const r = new Request('http://localhost:3000/api/ai/stream', {
      method: 'POST',
      headers: { ...admin, 'content-type': 'application/json' },
      body: JSON.stringify({ scope: 'events', prompt: '__HANG__' }),
      signal: ac.signal,
    });
    const res = await streamRoute(r);
    const reader = res.body!.getReader();
    await reader.read();
    setTimeout(() => ac.abort(), 300);
    let all = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      all += new TextDecoder().decode(value);
    }
    expect(all, all.slice(-400)).toContain('"status":"cancelled"');
  }, 20_000);
});
