// POST：在 hub 主機跑 Claude Code／Codex，用 SSE 串流事件（文字、工具呼叫、結果）。斷線就整棵行程收掉。
import crypto from 'node:crypto';
import { isIP } from 'node:net';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import { aiAnalyses } from '@/drizzle/schema';
import { audit } from '@/lib/audit';
import { actorOf, apiWrite } from '@/lib/auth/api';
import type { AiEvent } from '@/lib/ai/events';
import { PROVIDERS, resolveBin, runAi, running, SCOPE_PROMPTS, SYSTEM_PROMPT, type Provider } from '@/lib/ai/run';
import { getDb } from '@/lib/db';
import { error, parseCookies, readJson, sourceIp } from '@/lib/http';
import { LANG_COOKIE, resolveLang } from '@/lib/i18n/core';
import { readEnv } from '@/lib/env';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 900;

const Body = z.object({
  provider: z.enum(['claude', 'codex']).optional(),
  scope: z.enum(['fleet', 'connections', 'indicator', 'traffic', 'events', 'agent']).default('fleet'),
  indicator: z.string().max(64).refine((s) => isIP(s) > 0).optional(),
  agent_id: z.string().max(64).optional(),
  prompt: z.string().max(4000).optional(),
  max_turns: z.number().int().min(1).max(30).default(12),
});

const MAX_EVENTS = 400;

export async function POST(req: Request): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 16 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const max = Number(readEnv('ASA_HUB_AI_MAX_CONCURRENT') || 2) || 2;
  if (running() >= max) return error(429, 'too_many_running');
  const order: Provider[] = body.provider ? [body.provider] : PROVIDERS;
  const picked = order.map((p) => ({ p, bin: resolveBin(p) })).find((x) => x.bin);
  if (!picked?.bin) return error(503, 'no_ai_cli', { hint: 'install and sign in to claude or codex on the hub host' });
  if (body.scope === 'agent' && !body.agent_id) return error(400, 'bad_request', { rule: 'agent_id' });
  if (body.scope === 'indicator' && !body.indicator) return error(400, 'bad_request', { rule: 'indicator' });

  const lang = resolveLang(parseCookies(req)[LANG_COOKIE], req.headers.get('accept-language'));
  const base = body.prompt?.trim() || (lang === 'en' ? SCOPE_PROMPTS[body.scope].en : SCOPE_PROMPTS[body.scope].zh);
  // 指定裝置時只看那一台（每種範圍都適用）
  let prompt = body.indicator ? `${base}\n\nIP: ${body.indicator}` : base;
  if (body.agent_id) prompt += `\n\n${lang === 'en' ? 'Only look at this host' : '只看這一台主機'}：agent_id: ${body.agent_id}`;
  const id = `ai_${crypto.randomBytes(8).toString('hex')}`;
  const actor = actorOf(who);
  const db = getDb();
  await db.insert(aiAnalyses).values({ id, provider: picked.p, scope: body.scope, agentId: body.agent_id ?? null, prompt, createdBy: actor });
  await audit({ actor, actorRole: 'admin', action: 'ai.run', targetType: 'ai_analysis', targetId: id, sourceIp: sourceIp(req), details: { provider: picked.p, scope: body.scope } });

  const enc = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let open = true;
      const send = (obj: unknown) => {
        if (!open) return;
        try {
          controller.enqueue(enc.encode(`data: ${JSON.stringify(obj)}\n\n`));
        } catch {
          open = false;
        }
      };
      const ping = setInterval(() => {
        if (!open) return;
        try {
          controller.enqueue(enc.encode(': ping\n\n'));
        } catch {
          open = false;
        }
      }, 15_000);
      const kept: AiEvent[] = [];
      send({ type: 'start', id, provider: picked.p });
      const result = await runAi(
        { provider: picked.p, prompt, system: SYSTEM_PROMPT(lang), maxTurns: body.max_turns, timeoutMs: 10 * 60_000 },
        picked.bin!,
        (e) => {
          if (e.type !== 'text' && kept.length < MAX_EVENTS) kept.push(e);
          send(e);
        },
        req.signal,
      ).catch((e: unknown) => ({ text: '', isError: true, toolsCalled: 0, cancelled: false, stderr: e instanceof Error ? e.message : String(e) }));
      const status = result.cancelled ? 'cancelled' : result.isError ? 'error' : 'done';
      await db
        .update(aiAnalyses)
        .set({
          status,
          finishedAt: new Date(),
          resultText: result.text.slice(0, 200_000),
          toolsCalled: result.toolsCalled,
          events: kept,
          error: result.isError ? result.stderr.slice(-4000) : null,
        })
        .where(eq(aiAnalyses.id, id));
      send({ type: 'end', id, status, error: result.isError ? result.stderr.split('\n').filter(Boolean).slice(-5).join('\n') : undefined });
      clearInterval(ping);
      open = false;
      try {
        controller.close();
      } catch {
        // 用戶端已斷線
      }
    },
  });
  return new Response(stream, {
    headers: { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store', 'x-accel-buffering': 'no' },
  });
}
