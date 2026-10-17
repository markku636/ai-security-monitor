'use client';

// 「設定與金鑰 → 資料清除」：三種歷史（AI 分析、連線歷史、外部情資快取）各一張卡，可全部清或只清 N 天以前的。
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { Hint } from '@/components/ui/Hint';
import { utc } from '@/lib/format';
import { useT } from '@/lib/i18n/client';

type Kind = 'ai' | 'connections' | 'ipintel';
interface Stat {
  count: number;
  oldest: string | null;
  retentionDays: number | null;
}

const BTN_DANGER = 'rounded-md border border-red-300 px-3 py-1 text-sm text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950/40';
const FIELD = 'rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900';

export function HistoryCleaner({ initial, agents }: { initial: Record<Kind, Stat>; agents: { id: string; hostname: string }[] }) {
  const { t } = useT();
  const router = useRouter();
  const [stats, setStats] = useState(initial);
  const [busy, setBusy] = useState<Kind | null>(null);
  const [msg, setMsg] = useState<{ kind: Kind; ok: boolean; text: string } | null>(null);
  const [scope, setScope] = useState<Record<Kind, 'all' | 'older'>>({ ai: 'all', connections: 'all', ipintel: 'all' });
  const [days, setDays] = useState<Record<Kind, number>>({ ai: 30, connections: 30, ipintel: 30 });
  const [agent, setAgent] = useState('');
  const [cli, setCli] = useState(true);

  const info: Record<Kind, { title: string; desc: string; hint: string; unit: string }> = {
    ai: {
      title: t('AI 分析紀錄'),
      desc: t('AI 助手「最近的分析」：問的問題、AI 的回答與查過哪些資料。執行中的不會刪。'),
      hint: t('紀錄裡有送給 AI 的主機資料（主機名稱、IP、程式）。不需要時可以清掉。'),
      unit: t('筆分析'),
    },
    connections: {
      title: t('連線歷史（可疑 IP 排名）'),
      desc: t('每台主機看過的遠端位址與次數，是「可疑 IP 排名」的累計來源。清掉後排名重新從零累計；IP 備註保留。'),
      hint: t('只清 Hub 上的累計；各主機自己用來判斷週期性連線的短期歷史不受影響。'),
      unit: t('個目的地'),
    },
    ipintel: {
      title: t('外部情資查詢快取'),
      desc: t('IP 分析頁查過的 AbuseIPDB、GreyNoise、IPinfo 等結果。清掉後要重新按「查詢」，會再用掉外部服務的額度。'),
      hint: t('快取是為了不重複查同一個 IP、省外部服務的每日額度。'),
      unit: t('個 IP'),
    },
  };

  const clear = async (k: Kind) => {
    const s = stats[k];
    const range = scope[k] === 'older' ? t('{n} 天以前的', { n: days[k] }) : t('全部');
    const host = k === 'connections' && agent ? t('（只限 {h}）', { h: agents.find((a) => a.id === agent)?.hostname ?? agent }) : '';
    if (!window.confirm(t('清除{range}{title}{host}？目前共 {n} {unit}，清除後無法復原。', { range, title: info[k].title, host, n: s.count, unit: info[k].unit }))) return;
    setBusy(k);
    setMsg(null);
    const q = new URLSearchParams({ kind: k });
    if (scope[k] === 'older') q.set('older_than_days', String(days[k]));
    if (k === 'connections' && agent) q.set('agent_id', agent);
    if (k === 'ai' && cli) q.set('cli', '1');
    try {
      const res = await fetch(`/api/v1/admin/history?${q}`, { method: 'DELETE', headers: { 'x-asa-request': '1' }, credentials: 'same-origin' });
      const j = (await res.json().catch(() => ({}))) as { deleted?: number; stats?: Record<Kind, Stat>; cli?: { claude: number; codex: number; skipped: string[] } | null; error?: string };
      if (!res.ok) {
        setMsg({ kind: k, ok: false, text: t('清除失敗：{e}', { e: j.error ?? String(res.status) }) });
        return;
      }
      if (j.stats) setStats(j.stats);
      const extra = j.cli ? t('；AI 程式的對話紀錄：Claude {c} 個、Codex {x} 個', { c: j.cli.claude, x: j.cli.codex }) : '';
      setMsg({ kind: k, ok: true, text: t('已清除 {n} {unit}', { n: j.deleted ?? 0, unit: info[k].unit }) + extra });
      router.refresh();
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {(['ai', 'connections', 'ipintel'] as Kind[]).map((k) => {
        const s = stats[k];
        return (
          <section key={k} className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">
              {info[k].title}
              <Hint text={info[k].hint} />
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-300">{info[k].desc}</p>
            <div className="text-sm">
              <span className="text-2xl font-semibold tabular-nums">{s.count.toLocaleString()}</span> <span className="text-slate-500">{info[k].unit}</span>
              <div className="text-xs text-slate-500">
                {s.oldest ? t('最舊：{at}', { at: utc(s.oldest) }) : t('目前沒有資料')}
                {s.retentionDays != null ? ` · ${s.retentionDays > 0 ? t('自動保留 {n} 天', { n: s.retentionDays }) : t('不自動清除')}` : ''}
              </div>
            </div>
            <div className="space-y-2 text-sm">
              <label className="flex items-center gap-2">
                <input type="radio" name={`scope-${k}`} className="accent-teal-700" checked={scope[k] === 'all'} onChange={() => setScope({ ...scope, [k]: 'all' })} />
                {t('全部')}
              </label>
              <label className="flex items-center gap-2">
                <input type="radio" name={`scope-${k}`} className="accent-teal-700" checked={scope[k] === 'older'} onChange={() => setScope({ ...scope, [k]: 'older' })} />
                {k === 'connections' ? t('超過') : t('早於')}
                <input
                  type="number"
                  min={1}
                  max={3650}
                  className={`${FIELD} w-20`}
                  value={days[k]}
                  onChange={(e) => setDays({ ...days, [k]: Math.max(1, Math.min(3650, Number(e.target.value) || 1)) })}
                  onFocus={() => setScope({ ...scope, [k]: 'older' })}
                />
                {k === 'connections' ? t('天沒再看到的') : t('天以前的')}
              </label>
              {k === 'connections' && agents.length > 1 ? (
                <label className="flex items-center gap-2">
                  {t('主機')}
                  <select className={FIELD} value={agent} onChange={(e) => setAgent(e.target.value)}>
                    <option value="">{t('所有主機')}</option>
                    {agents.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.hostname}
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}
              {k === 'ai' ? (
                <label className="flex items-start gap-2">
                  <input type="checkbox" className="mt-1 accent-teal-700" checked={cli} onChange={(e) => setCli(e.target.checked)} />
                  <span>
                    {t('一併刪除 AI 程式留下的對話紀錄')}
                    <Hint text={t('Claude Code／Codex 自己也會在 Hub 的資料目錄留一份對話紀錄（內含送給 AI 的資料）。勾了就一起刪；不會刪登入資料。')} />
                  </span>
                </label>
              ) : null}
            </div>
            <div className="mt-auto flex flex-wrap items-center gap-3">
              <button type="button" className={BTN_DANGER} disabled={busy !== null || s.count === 0} onClick={() => void clear(k)}>
                {busy === k ? t('清除中…') : t('清除')}
              </button>
              {msg?.kind === k ? <span className={`text-sm ${msg.ok ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'}`}>{msg.text}</span> : null}
            </div>
          </section>
        );
      })}
    </div>
  );
}

/** AI 助手「最近的分析」每一筆的「刪除」。 */
export function DeleteAnalysisButton({ id }: { id: string }) {
  const { t } = useT();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  return (
    <button
      type="button"
      className="rounded px-1.5 text-xs text-slate-500 hover:text-red-700 hover:underline disabled:opacity-50 dark:hover:text-red-400"
      disabled={busy}
      title={t('刪除這筆分析紀錄')}
      onClick={async () => {
        if (!window.confirm(t('刪除這筆分析紀錄？無法復原。'))) return;
        setBusy(true);
        await fetch(`/api/ai/analyses/${id}`, { method: 'DELETE', headers: { 'x-asa-request': '1' }, credentials: 'same-origin' });
        setBusy(false);
        router.refresh();
      }}
    >
      {t('刪除')}
    </button>
  );
}
