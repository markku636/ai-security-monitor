// claude stream-json／codex exec --json 的 JSONL → 共同事件（與 agent/src/ai/events.rs 相同對應）。

export type AiEvent =
  | { type: 'init'; model?: string }
  | { type: 'text'; text: string }
  | { type: 'tool'; name: string; input?: string }
  | { type: 'tool_result'; ok: boolean; preview: string }
  | { type: 'done'; text?: string; is_error: boolean; duration_ms?: number; cost_usd?: number }
  | { type: 'error'; message: string };

type J = Record<string, unknown>;
const obj = (v: unknown): J => (v && typeof v === 'object' && !Array.isArray(v) ? (v as J) : {});
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

export function stripMcpPrefix(name: string): string {
  const m = /^mcp__[^_]+(?:_[^_]+)*?__(.+)$/.exec(name);
  return m ? m[1] : name;
}

function clip(s: string, n: number): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > n ? `${one.slice(0, n)}…` : one;
}

function inputDisplay(v: unknown): string | undefined {
  if (v === null || v === undefined) return undefined;
  if (typeof v === 'object' && !Array.isArray(v) && Object.keys(v as J).length === 0) return undefined;
  return clip(JSON.stringify(v), 160);
}

function resultText(c: unknown): string {
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.map((b) => str(obj(b).text) ?? '').join('\n');
  return c === undefined ? '' : JSON.stringify(c);
}

export function claudeEvents(line: string, st: { streamed: boolean }): AiEvent[] {
  let v: J;
  try {
    v = obj(JSON.parse(line));
  } catch {
    return [];
  }
  const out: AiEvent[] = [];
  const blocks = (): J[] => {
    const c = obj(v.message).content;
    return Array.isArray(c) ? c.map(obj) : [];
  };
  switch (v.type) {
    case 'system':
      if (v.subtype === 'init') out.push({ type: 'init', model: str(v.model) });
      break;
    case 'stream_event': {
      const e = obj(v.event);
      const d = obj(e.delta);
      if (e.type === 'content_block_delta' && d.type === 'text_delta' && typeof d.text === 'string') {
        st.streamed = true;
        out.push({ type: 'text', text: d.text });
      }
      break;
    }
    case 'assistant':
      for (const b of blocks()) {
        if (b.type === 'tool_use') out.push({ type: 'tool', name: stripMcpPrefix(str(b.name) ?? 'tool'), input: inputDisplay(b.input) });
        else if (b.type === 'text' && !st.streamed && typeof b.text === 'string') out.push({ type: 'text', text: b.text });
      }
      break;
    case 'user':
      for (const b of blocks()) {
        if (b.type === 'tool_result') out.push({ type: 'tool_result', ok: b.is_error !== true, preview: clip(resultText(b.content), 200) });
      }
      break;
    case 'result':
      out.push({
        type: 'done',
        text: str(v.result),
        is_error: v.is_error === true,
        duration_ms: typeof v.duration_ms === 'number' ? v.duration_ms : undefined,
        cost_usd: typeof v.total_cost_usd === 'number' ? v.total_cost_usd : undefined,
      });
      break;
  }
  return out;
}

export function codexEvents(line: string, st: { lastText?: string }, elapsedMs: number): AiEvent[] {
  let v: J;
  try {
    v = obj(JSON.parse(line));
  } catch {
    return [];
  }
  const item = obj(v.item);
  const tool = () => stripMcpPrefix(str(item.tool) ?? str(item.name) ?? 'mcp');
  switch (v.type) {
    case 'thread.started':
      return [{ type: 'init' }];
    case 'item.started':
      return item.type === 'mcp_tool_call' ? [{ type: 'tool', name: tool(), input: inputDisplay(item.arguments) }] : [];
    case 'item.completed':
      if (item.type === 'agent_message' && typeof item.text === 'string' && item.text) {
        st.lastText = item.text;
        return [{ type: 'text', text: item.text }];
      }
      if (item.type === 'mcp_tool_call') {
        const err = item.error === null || item.error === undefined ? undefined : typeof item.error === 'string' ? item.error : JSON.stringify(item.error);
        const r = obj(item.result);
        return [{ type: 'tool_result', ok: !err && item.status !== 'failed', preview: clip(err ?? resultText(r.content ?? item.result), 200) }];
      }
      return [];
    case 'turn.completed':
      return [{ type: 'done', text: st.lastText, is_error: false, duration_ms: elapsedMs }];
    case 'turn.failed':
      return [{ type: 'done', text: str(obj(v.error).message) ?? str(v.message), is_error: true, duration_ms: elapsedMs }];
    case 'error':
      return [{ type: 'error', message: str(v.message) ?? '' }];
    default:
      return [];
  }
}
