'use client';

// 可疑 IP 排名的批次操作：每列勾選、全選本頁、操作列（批次查外部情資／請 AI 分析／清除選取）。
// 表格本身仍是 server component，這裡只管勾選狀態與按鈕；查完 router.refresh() 讓「外部風險」欄更新。
import { useRouter } from 'next/navigation';
import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { AI_MAX_IPS } from '@/lib/ai/scope';
import { useT } from '@/lib/i18n/client';

/** 每次送幾個 IP 給 /api/v1/ip-intel/batch（小批才能顯示進度，也不會碰到請求逾時）。 */
const CHUNK = 5;

interface Row {
  ip: string;
  /** 內網／保留位址不送外部查詢。 */
  isPublic: boolean;
}

interface Ctx {
  rows: Row[];
  selected: Set<string>;
  toggle: (ip: string) => void;
  setAll: (on: boolean) => void;
  clear: () => void;
}

const SelectionContext = createContext<Ctx | null>(null);

function useSelection(): Ctx {
  const c = useContext(SelectionContext);
  if (!c) throw new Error('IpSelection components must be inside <IpSelectionProvider>');
  return c;
}

export function IpSelectionProvider({ rows, children }: { rows: Row[]; children: ReactNode }) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // 換頁／換排序後只保留還在畫面上的 IP
  const key = rows.map((r) => r.ip).join(',');
  useEffect(() => {
    const visible = new Set(key.split(','));
    setSelected((s) => {
      const kept = [...s].filter((ip) => visible.has(ip));
      return kept.length === s.size ? s : new Set(kept);
    });
  }, [key]);
  const value = useMemo<Ctx>(
    () => ({
      rows,
      selected,
      toggle: (ip) =>
        setSelected((s) => {
          const n = new Set(s);
          if (n.has(ip)) n.delete(ip);
          else n.add(ip);
          return n;
        }),
      setAll: (on) => setSelected(on ? new Set(rows.map((r) => r.ip)) : new Set()),
      clear: () => setSelected(new Set()),
    }),
    [rows, selected],
  );
  return <SelectionContext.Provider value={value}>{children}</SelectionContext.Provider>;
}

const BOX = 'h-4 w-4 cursor-pointer accent-teal-700';

export function IpSelectCheckbox({ ip }: { ip: string }) {
  const { t } = useT();
  const { selected, toggle } = useSelection();
  return <input type="checkbox" className={BOX} checked={selected.has(ip)} onChange={() => toggle(ip)} aria-label={t('選取 {ip}', { ip })} />;
}

export function IpSelectAll() {
  const { t } = useT();
  const { rows, selected, setAll } = useSelection();
  const ref = useRef<HTMLInputElement>(null);
  const all = rows.length > 0 && selected.size === rows.length;
  const some = selected.size > 0 && !all;
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = some;
  }, [some]);
  return (
    <input
      ref={ref}
      type="checkbox"
      className={BOX}
      checked={all}
      onChange={() => setAll(!all)}
      aria-label={t('全選本頁')}
      title={t('全選本頁')}
    />
  );
}

interface Progress {
  done: number;
  total: number;
}

interface Outcome {
  queried: number;
  cached: number;
  skipped: number;
  errors: number;
}

interface BatchItem {
  ip: string;
  cached: boolean;
  skipped?: string;
  error?: string;
}

const BTN = 'rounded-md border px-2.5 py-1 text-xs disabled:cursor-not-allowed disabled:opacity-50';
const PRIMARY = `${BTN} border-teal-700 bg-teal-700 text-white hover:bg-teal-800`;
const SECONDARY = `${BTN} border-teal-600 text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950`;
const PLAIN = `${BTN} border-slate-300 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800`;

/** 操作列：沒勾時只有「全部查詢」，勾了之後出現批次動作。 */
export function IpBatchBar() {
  const { t } = useT();
  const router = useRouter();
  const { rows, selected, clear } = useSelection();
  const [force, setForce] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const busy = progress !== null;
  const picked = rows.filter((r) => selected.has(r.ip));
  const n = picked.length;

  async function run(list: Row[]) {
    setOutcome(null);
    setMessage(null);
    const pub = list.filter((r) => r.isPublic).map((r) => r.ip);
    const privateCount = list.length - pub.length;
    if (!pub.length) {
      setMessage(t('選取的都是內網或保留位址，這些不會送給外部情資來源查詢。'));
      return;
    }
    const acc: Outcome = { queried: 0, cached: 0, skipped: privateCount, errors: 0 };
    setProgress({ done: 0, total: pub.length });
    try {
      for (let i = 0; i < pub.length; i += CHUNK) {
        const chunk = pub.slice(i, i + CHUNK);
        const res = await fetch('/api/v1/ip-intel/batch', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-asa-request': '1' },
          body: JSON.stringify({ ips: chunk, force }),
        });
        const j = (await res.json().catch(() => ({}))) as { error?: string; items?: BatchItem[] };
        if (!res.ok) {
          setMessage(
            j.error === 'lookups_disabled'
              ? t('外部查詢已被關閉（ASA_HUB_IP_LOOKUPS=off），沒有送出任何 IP。')
              : t('查詢失敗：{error}', { error: j.error ?? String(res.status) }),
          );
          break;
        }
        for (const it of j.items ?? []) {
          if (it.skipped) acc.skipped += 1;
          else if (it.error) acc.errors += 1;
          else if (it.cached) acc.cached += 1;
          else acc.queried += 1;
        }
        setProgress({ done: Math.min(pub.length, i + chunk.length), total: pub.length });
      }
    } catch (e) {
      setMessage(t('查詢失敗：{error}', { error: e instanceof Error ? e.message : String(e) }));
    } finally {
      setProgress(null);
      setOutcome(acc);
      router.refresh();
    }
  }

  function runAll() {
    const pub = rows.filter((r) => r.isPublic).length;
    if (!pub) {
      setMessage(t('這一頁都是內網或保留位址，這些不會送給外部情資來源查詢。'));
      return;
    }
    if (!window.confirm(t('要把這一頁 {n} 個公網 IP 送給已啟用的外部情資來源查詢嗎？會用掉各來源的每日免費額度（查過、還在快取內的不會重打）。', { n: pub }))) return;
    void run(rows);
  }

  const aiHref = `/ai?scope=ips&ips=${encodeURIComponent(picked.map((r) => r.ip).join(','))}`;
  const tooManyForAi = n > AI_MAX_IPS;

  return (
    <div className="mb-2 space-y-2">
      <div
        className={`flex flex-wrap items-center gap-2 rounded-lg px-2 py-1.5 text-xs ${n ? 'bg-teal-50 ring-1 ring-teal-600/30 dark:bg-teal-950/60' : ''}`}
        role="toolbar"
        aria-label={t('批次操作')}
      >
        {n ? (
          <>
            <span className="font-medium text-slate-700 dark:text-slate-200">{t('已選 {n} 個 IP', { n })}</span>
            <button type="button" className={PRIMARY} disabled={busy} onClick={() => void run(picked)} title={t('把勾選的公網 IP 送給已啟用的外部情資來源（AbuseIPDB、GreyNoise 等）查風險分數；內網位址會自動略過。')}>
              {t('查詢外部情資（{n} 個）', { n })}
            </button>
            {tooManyForAi ? (
              <button type="button" className={SECONDARY} disabled title={t('AI 一次最多分析 {max} 個 IP，請少勾一些', { max: AI_MAX_IPS })}>
                {t('請 AI 分析選取的 IP')}
              </button>
            ) : (
              <a
                href={aiHref}
                className={SECONDARY}
                aria-disabled={busy}
                title={t('開 AI 助手，把這些 IP 的連線紀錄、黑名單命中、備註與外部情資一起交給 AI 判讀（唯讀，不會改任何設定）。')}
              >
                {t('請 AI 分析選取的 IP')}
              </a>
            )}
            <button type="button" className={PLAIN} disabled={busy} onClick={clear}>
              {t('清除選取')}
            </button>
          </>
        ) : (
          <>
            <span className="text-slate-500">{t('勾選左邊的方框可以一次查多個 IP，或：')}</span>
            <button type="button" className={SECONDARY} disabled={busy || !rows.length} onClick={runAll}>
              {t('全部查詢（前 {n} 名）', { n: rows.length })}
            </button>
          </>
        )}
        <label
          className="ml-auto inline-flex cursor-pointer items-center gap-1 text-slate-500"
          title={t('平常查過的 IP 在快取有效期間（約一天）不會重打外部來源；勾這個會強制重新查詢，會多用額度。')}
        >
          <input type="checkbox" className="h-3.5 w-3.5 accent-teal-700" checked={force} onChange={(e) => setForce(e.target.checked)} disabled={busy} />
          {t('略過快取重查')} ⓘ
        </label>
      </div>
      {progress ? (
        <div className="space-y-1" role="status" aria-live="polite">
          <div className="text-xs text-slate-600 dark:text-slate-300">{t('已查 {done}／{total}', { ...progress })}</div>
          <div className="h-1.5 w-full overflow-hidden rounded bg-slate-200 dark:bg-slate-700">
            <div className="h-full bg-teal-600 transition-all" style={{ width: `${Math.round((100 * progress.done) / Math.max(1, progress.total))}%` }} />
          </div>
        </div>
      ) : null}
      {outcome && !progress ? (
        <p className="text-xs text-slate-600 dark:text-slate-300" role="status">
          {t('完成：新查 {queried} 個、用快取 {cached} 個、略過 {skipped} 個、失敗 {errors} 個。分數已更新在「外部風險」欄。', { ...outcome })}
        </p>
      ) : null}
      {message ? <p className="text-xs text-amber-700 dark:text-amber-300">{message}</p> : null}
    </div>
  );
}
