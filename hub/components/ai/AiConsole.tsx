'use client';

// AI 分析主控台：選範圍與 AI，送出後以 SSE 即時顯示回答文字與工具呼叫；可中途停止。
import { useRouter } from 'next/navigation';
import { useRef, useState } from 'react';
import { useT } from '@/lib/i18n/client';

type Ev =
  | { type: 'start'; id: string; provider: string }
  | { type: 'text'; text: string }
  | { type: 'tool'; name: string; input?: string }
  | { type: 'tool_result'; ok: boolean; preview: string }
  | { type: 'done'; is_error: boolean }
  | { type: 'error'; message: string }
  | { type: 'end'; id: string; status: string; error?: string }
  | { type: 'init'; model?: string };

interface Line {
  kind: 'tool' | 'tool_err' | 'note';
  text: string;
}

export function AiConsole({
  providers,
  agents,
  initialScope,
  initialAgent,
}: {
  providers: { id: string; available: boolean }[];
  agents: { id: string; hostname: string }[];
  initialScope: string;
  initialAgent?: string;
}) {
  const { t } = useT();
  const router = useRouter();
  const available = providers.filter((p) => p.available);
  const [provider, setProvider] = useState(available[0]?.id ?? '');
  const [scope, setScope] = useState(initialScope);
  const [agent, setAgent] = useState(initialAgent ?? agents[0]?.id ?? '');
  const [prompt, setPrompt] = useState('');
  const [answer, setAnswer] = useState('');
  const [lines, setLines] = useState<Line[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const busy = status === 'running';

  const scopes: [string, string][] = [
    ['fleet', t('整個車隊')],
    ['agent', t('單一主機')],
    ['traffic', t('解讀流量')],
    ['events', t('分析當機與資安事件')],
  ];

  async function start() {
    setAnswer('');
    setLines([]);
    setStatus('running');
    const ac = new AbortController();
    abort.current = ac;
    try {
      const res = await fetch('/api/ai/stream', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-asa-request': '1' },
        body: JSON.stringify({ provider: provider || undefined, scope, agent_id: scope === 'agent' ? agent : undefined, prompt: prompt.trim() || undefined }),
        signal: ac.signal,
      });
      if (!res.ok || !res.body) {
        const j = (await res.json().catch(() => ({}))) as { error?: string };
        setStatus('error');
        setLines([{ kind: 'note', text: t('無法開始：{error}', { error: j.error ?? String(res.status) }) }]);
        return;
      }
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i: number;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const chunk = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const data = chunk
            .split('\n')
            .filter((l) => l.startsWith('data: '))
            .map((l) => l.slice(6))
            .join('');
          if (!data) continue;
          const e = JSON.parse(data) as Ev;
          if (e.type === 'text') setAnswer((a) => a + e.text);
          else if (e.type === 'tool') setLines((l) => [...l, { kind: 'tool', text: `${e.name} ${e.input ?? ''}` }]);
          else if (e.type === 'tool_result' && !e.ok) setLines((l) => [...l, { kind: 'tool_err', text: e.preview }]);
          else if (e.type === 'error') setLines((l) => [...l, { kind: 'note', text: e.message }]);
          else if (e.type === 'end') {
            setStatus(e.status);
            if (e.error) setLines((l) => [...l, { kind: 'note', text: e.error! }]);
          }
        }
      }
    } catch {
      setStatus('cancelled');
    } finally {
      abort.current = null;
      router.refresh();
    }
  }

  if (!available.length) {
    return (
      <div className="rounded-xl border border-dashed border-slate-300 p-6 text-sm dark:border-slate-700">
        <p className="font-medium">{t('Hub 主機上找不到 Claude Code 或 Codex CLI')}</p>
        <p className="mt-1 text-slate-500">{t('在 hub 主機安裝並登入其中一個（npm i -g @anthropic-ai/claude-code 或 @openai/codex），或設定 ASA_HUB_CLAUDE_BIN／ASA_HUB_CODEX_BIN。')}</p>
      </div>
    );
  }

  const field = 'rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900';
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
        <label className="flex flex-col gap-1 text-xs text-slate-500">
          {t('範圍')}
          <select className={field} value={scope} onChange={(e) => setScope(e.target.value)} disabled={busy}>
            {scopes.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </label>
        {scope === 'agent' ? (
          <label className="flex flex-col gap-1 text-xs text-slate-500">
            {t('主機')}
            <select className={field} value={agent} onChange={(e) => setAgent(e.target.value)} disabled={busy}>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <label className="flex flex-col gap-1 text-xs text-slate-500">
          AI
          <select className={field} value={provider} onChange={(e) => setProvider(e.target.value)} disabled={busy}>
            {available.map((p) => (
              <option key={p.id} value={p.id}>
                {p.id === 'claude' ? 'Claude Code' : 'Codex CLI'}
              </option>
            ))}
          </select>
        </label>
        <label className="flex min-w-64 flex-1 flex-col gap-1 text-xs text-slate-500">
          {t('問題（留空用預設）')}
          <input className={field} value={prompt} onChange={(e) => setPrompt(e.target.value)} disabled={busy} maxLength={4000} />
        </label>
        {busy ? (
          <button type="button" onClick={() => abort.current?.abort()} className="rounded-md border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-700">
            {t('停止')}
          </button>
        ) : (
          <button type="button" onClick={start} className="rounded-md bg-teal-700 px-3 py-1.5 text-sm text-white hover:bg-teal-800">
            {t('開始分析')}
          </button>
        )}
      </div>
      {lines.length || answer || status ? (
        <div className="space-y-2 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          {lines.map((l, i) => (
            <div
              key={i}
              className={`font-mono text-xs ${l.kind === 'tool' ? 'text-sky-700 dark:text-sky-300' : l.kind === 'tool_err' ? 'text-red-700 dark:text-red-400' : 'text-amber-700 dark:text-amber-300'}`}
            >
              {l.kind === 'tool' ? '⚙ ' : l.kind === 'tool_err' ? '✗ ' : '! '}
              {l.text}
            </div>
          ))}
          {answer ? <div className="whitespace-pre-wrap text-sm leading-relaxed">{answer}</div> : null}
          {status && status !== 'running' ? (
            <div className="text-xs text-slate-500">
              {status === 'done' ? t('完成') : status === 'cancelled' ? t('已停止') : t('發生錯誤')}
            </div>
          ) : busy ? (
            <div className="text-xs text-slate-500" role="status">
              {t('分析中…')}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
