// Hub MCP（Streamable HTTP，協定照 agent 端與 db-kit）：POST JSON-RPC；initialize 回 Mcp-Session-Id；純通知 202。
// 認證：ASA_HUB_MCP_TOKEN 或管理員金鑰（Bearer）。開放模式（沒設管理員金鑰）只接受 Host／Origin 是本機的請求。
//   claude mcp add --transport http asahub http://<hub>/api/mcp --header "Authorization: Bearer <token>"
import crypto from 'node:crypto';
import { safeEqual } from '@/lib/auth/crypto';
import { bearer } from '@/lib/auth/access';
import { env, isOpenMode } from '@/lib/env';
import { readJson } from '@/lib/http';
import { isRunToken } from '@/lib/ai/run';
import { callTool, TOOLS } from '@/lib/mcp/tools';

export const dynamic = 'force-dynamic';

const PROTOCOL = '2025-06-18';
const SUPPORTED = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_BODY = 4 * 1024 * 1024;

const g = globalThis as unknown as { __asaMcpSessions?: string[] };
const sessions = () => (g.__asaMcpSessions ??= []);

function loopback(h: string | null): boolean {
  if (!h) return false;
  const host = h.replace(/^https?:\/\//, '').split('/')[0];
  const name = host.startsWith('[') ? host.slice(1, host.indexOf(']')) : host.split(':')[0];
  return name === 'localhost' || name === '127.0.0.1' || name === '::1';
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
}

function authorized(req: Request): boolean {
  const token = bearer(req);
  const mcpToken = (process.env.ASA_HUB_MCP_TOKEN ?? '').trim();
  if (token && mcpToken && safeEqual(token, mcpToken)) return true;
  // hub 自己跑 AI 時給 CLI 的一次性 token
  if (token && isRunToken(token)) return true;
  if (token && env().adminSecret && safeEqual(token, env().adminSecret)) return true;
  if (isOpenMode()) {
    const origin = req.headers.get('origin');
    return loopback(req.headers.get('host')) && (!origin || loopback(origin));
  }
  return false;
}

const ok = (id: unknown, result: unknown) => ({ jsonrpc: '2.0', id, result });
const err = (id: unknown, code: number, message: string) => ({ jsonrpc: '2.0', id, error: { code, message } });

async function handle(msg: Record<string, unknown>): Promise<unknown | null> {
  const method = typeof msg.method === 'string' ? msg.method : null;
  const id = msg.id;
  if (!method || id === undefined || id === null) return null;
  const params = (msg.params ?? {}) as Record<string, unknown>;
  switch (method) {
    case 'initialize': {
      const asked = typeof params.protocolVersion === 'string' ? params.protocolVersion : PROTOCOL;
      return ok(id, {
        protocolVersion: SUPPORTED.includes(asked) ? asked : PROTOCOL,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'asa-hub', version: env().version },
        instructions:
          'Read-only access to the Security Hub fleet: agents, findings, connections, threat-intel hits, traffic, crashes and security events. Always cite intel vendors and source_url; never claim to have changed anything.',
      });
    }
    case 'ping':
      return ok(id, {});
    case 'tools/list':
      return ok(id, { tools: TOOLS.map((t) => ({ ...t, annotations: { readOnlyHint: true } })) });
    case 'tools/call': {
      const name = typeof params.name === 'string' ? params.name : '';
      if (!name) return err(id, -32602, 'Missing params.name');
      const args = (params.arguments && typeof params.arguments === 'object' ? params.arguments : {}) as Record<string, unknown>;
      try {
        const text = await callTool(name, args);
        return ok(id, { content: [{ type: 'text', text }], isError: false });
      } catch (e) {
        return ok(id, { content: [{ type: 'text', text: e instanceof Error ? e.message : String(e) }], isError: true });
      }
    }
    case 'resources/list':
      return ok(id, { resources: [] });
    case 'prompts/list':
      return ok(id, { prompts: [] });
    default:
      return err(id, -32601, `Method not found: ${method}`);
  }
}

export async function POST(req: Request): Promise<Response> {
  if (!authorized(req)) return json({ error: 'unauthorized' }, 401);
  let body: unknown;
  try {
    body = await readJson(req, MAX_BODY);
  } catch {
    return json(err(null, -32700, 'Parse error'), 400);
  }
  const isInit = !Array.isArray(body) && (body as { method?: string })?.method === 'initialize';
  const sid = req.headers.get('mcp-session-id');
  if (!isInit && sid && !sessions().includes(sid)) return json({ error: 'unknown_session' }, 404);
  let out: unknown;
  if (Array.isArray(body)) {
    const results = (await Promise.all(body.map((m) => handle(m as Record<string, unknown>)))).filter((x) => x !== null);
    out = results.length ? results : null;
  } else {
    out = await handle((body ?? {}) as Record<string, unknown>);
  }
  if (out === null) return new Response(null, { status: 202 });
  const headers: Record<string, string> = {};
  if (isInit) {
    const s = crypto.randomUUID();
    const list = sessions();
    list.push(s);
    if (list.length > 1024) list.shift();
    headers['mcp-session-id'] = s;
  }
  const accept = (req.headers.get('accept') ?? '').toLowerCase();
  if (accept.includes('text/event-stream') && !accept.includes('application/json')) {
    return new Response(`event: message\ndata: ${JSON.stringify(out)}\n\n`, {
      status: 200,
      headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-store', ...headers },
    });
  }
  return json(out, 200, headers);
}

export async function GET(): Promise<Response> {
  return json({ error: 'method_not_allowed' }, 405, { allow: 'POST, DELETE' });
}

export async function DELETE(req: Request): Promise<Response> {
  if (!authorized(req)) return json({ error: 'unauthorized' }, 401);
  const sid = req.headers.get('mcp-session-id');
  if (sid) g.__asaMcpSessions = sessions().filter((s) => s !== sid);
  return json({ ok: true });
}
