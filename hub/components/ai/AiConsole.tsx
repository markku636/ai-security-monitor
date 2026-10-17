'use client';

// AI 分析主控台：選範圍與 AI，送出後以 SSE 即時顯示回答文字與工具呼叫；可中途停止。
import { useRouter } from 'next/navigation';
import { useRef, useState } from 'react';
import { Markdown } from '@/components/ui/Markdown';
import { AI_MAX_IPS, splitIpList } from '@/lib/ai/scope';
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
  initialIndicator,
  initialIps,
}: {
  providers: { id: string; available: boolean }[];
  agents: { id: string; hostname: string }[];
  initialScope: string;
  initialAgent?: string;
  initialIndicator?: string;
  /** scope=ips：逗號分隔的 IP 清單（從可疑 IP 排名勾選帶過來）。 */
  initialIps?: string;
}) {
  const { t } = useT();
  const router = useRouter();
  const available = providers.filter((p) => p.available);
  const [provider, setProvider] = useState(available[0]?.id ?? '');
  const [scope, setScope] = useState(initialScope);
  const [agent, setAgent] = useState(initialAgent ?? '');
  const [indicator, setIndicator] = useState(initialIndicator ?? '');
  const [ipList, setIpList] = useState(initialIps ?? '');
  const ips = splitIpList(ipList);
  const [prompt, setPrompt] = useState('');
  const [answer, setAnswer] = useState('');
  const [lines, setLines] = useState<Line[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const busy = status === 'running';

  const scopes: [string, string][] = [
    ['fleet', t('整體狀況')],
    ['connections', t('分析可疑連線')],
    ['indicator', t('分析單一 IP')],
    ['ips', t('一次分析多個 IP')],
    ['agent', t('單一主機完整檢查')],
    ['traffic', t('解讀流量')],
    ['dns', t('解讀 DNS')],
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
        body: JSON.stringify({ provider: provider || undefined, scope, agent_id: agent || (scope === 'agent' ? agents[0]?.id : undefined), indicator: scope === 'indicator' ? indicator.trim() : undefined, ips: scope === 'ips' ? ips : undefined, prompt: prompt.trim() || undefined }),
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
          else if (e.type === 'error') setLines((l) => withLoginHint(l, e.message));
          else if (e.type === 'end') {
            setStatus(e.status);
            if (e.error) setLines((l) => withLoginHint(l, e.error!));
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

  // CLI 回「請登入／登入過期」時，多給一行提示指向上面的 AI 帳號卡
  function withLoginHint(l: Line[], text: string): Line[] {
    const next = [...l, { kind: 'note' as const, text }];
    if (/\/login|not logged in|login expired|invalid api key|authentication/i.test(text) && !l.some((x) => x.text === LOGIN_HINT)) next.push({ kind: 'note', text: LOGIN_HINT });
    return next;
  }
  const LOGIN_HINT = t('AI 還沒登入或登入已過期：請到上面的「AI 帳號」按「登入」。');

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
        {scope === 'indicator' ? (
          <label className="flex flex-col gap-1 text-xs text-slate-500">
            IP
            <input className={`${field} font-mono`} value={indicator} onChange={(e) => setIndicator(e.target.value)} disabled={busy} maxLength={64} placeholder="203.0.113.7" />
          </label>
        ) : null}
        {scope === 'ips' ? (
          <label className="flex min-w-64 flex-1 flex-col gap-1 text-xs text-slate-500" title={t('用逗號或空白分隔；在連線頁的「可疑 IP 排名」勾選後按「請 AI 分析選取的 IP」會自動帶入')}>
            {t('IP 清單（最多 {max} 個）', { max: AI_MAX_IPS })} ⓘ
            <textarea
              className={`${field} min-h-[2.25rem] font-mono`}
              value={ipList}
              onChange={(e) => setIpList(e.target.value)}
              disabled={busy}
              rows={Math.min(4, Math.max(1, Math.ceil(ips.length / 4)))}
              maxLength={2000}
              placeholder="203.0.113.7, 198.51.100.9"
            />
            <span className={ips.length > AI_MAX_IPS ? 'text-red-600 dark:text-red-400' : ''}>
              {t('{n} 個 IP；AI 會拿到每個 IP 的連線紀錄、黑名單命中、備註與外部情資快取', { n: ips.length })}
            </span>
          </label>
        ) : null}
        {agents.length ? (
          <label className="flex flex-col gap-1 text-xs text-slate-500">
            {t('裝置')}
            <select className={field} value={agent} onChange={(e) => setAgent(e.target.value)} disabled={busy}>
              {scope === 'agent' ? null : <option value="">{t('所有裝置')}</option>}
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
          <button
            type="button"
            onClick={start}
            disabled={scope === 'ips' && (!ips.length || ips.length > AI_MAX_IPS)}
            className="rounded-md bg-teal-700 px-3 py-1.5 text-sm text-white hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
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
          {answer ? <Markdown text={answer} /> : null}
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
