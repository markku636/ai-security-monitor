// 連線判定與方向的徽章、判定理由清單（含情資來源）。server／client 元件都能用（只吃 t）。
import type { TFn } from '@/lib/i18n/core';
import type { Reason } from '@/lib/queries/connections';

const VERDICT_STYLE: Record<string, string> = {
  dangerous: 'bg-verdict-dangerous text-white',
  suspicious: 'bg-verdict-suspicious text-white',
  unknown: 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200',
  safe: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
};

/** finding 狀態（server 與 client 元件共用，所以不能放在 'use client' 檔）。 */
export function statusText(t: TFn, s: string): string {
  return ({ open: t('未處理'), acked: t('已確認'), suppressed: t('已暫停'), resolved: t('已解決') } as Record<string, string>)[s] ?? s;
}

export function sevText(t: TFn, s: string): string {
  return ({ critical: t('嚴重'), high: t('高'), medium: t('中'), low: t('低'), info: t('資訊') } as Record<string, string>)[s] ?? s;
}

export function verdictLabel(t: TFn, v: string): string {
  return ({ dangerous: t('危險'), suspicious: t('可疑'), unknown: t('未知'), safe: t('安全') } as Record<string, string>)[v] ?? v;
}

export function VerdictChip({ verdict, t }: { verdict: string; t: TFn }) {
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-semibold ${VERDICT_STYLE[verdict] ?? VERDICT_STYLE.unknown}`}
    >
      {verdictLabel(t, verdict)}
    </span>
  );
}

export function directionLabel(t: TFn, d: string): string {
  return ({ outbound: t('對外'), inbound: t('對內'), listening: t('監聽'), local: t('本機') } as Record<string, string>)[d] ?? d;
}

const DIRECTION_ICON: Record<string, string> = { outbound: '↗', inbound: '↙', listening: '◉', local: '↺' };

export function DirectionBadge({ direction, t }: { direction: string; t: TFn }) {
  const tone =
    direction === 'inbound'
      ? 'border-violet-300 text-violet-700 dark:border-violet-700 dark:text-violet-300'
      : direction === 'outbound'
        ? 'border-sky-300 text-sky-700 dark:border-sky-700 dark:text-sky-300'
        : 'border-slate-300 text-slate-600 dark:border-slate-700 dark:text-slate-300';
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 text-xs ${tone}`}>
      <span aria-hidden>{DIRECTION_ICON[direction] ?? '·'}</span>
      {directionLabel(t, direction)}
    </span>
  );
}

export function anomalyLabel(t: TFn, kind: string): string {
  const m: Record<string, string> = {
    new_destination: t('新目的地'),
    new_listener: t('新的監聽 port'),
    risky_port: t('高風險 port'),
    beaconing: t('週期性連線（疑似 beacon）'),
    shell_with_network: t('命令列／腳本程式連網'),
    temp_dir_process: t('從暫存目錄執行'),
    unknown_exe: t('找不到執行檔'),
    exposed_listener: t('對所有介面開放'),
    failed_logon_burst_source: t('大量登入失敗來源'),
    tor_exit: t('Tor 出口節點'),
    off_hours: t('非上班時間'),
    high_volume_upload: t('大量上傳'),
    plaintext_protocol: t('明文協定'),
  };
  return m[kind] ?? kind;
}

/** 情資來源徽章：連到來源清單，滑過看授權、信心與抓取時間。 */
export function SourceBadge({ r, t }: { r: Reason; t: TFn }) {
  const title = [
    `${r.vendor ?? ''} · ${r.name ?? r.feed_id ?? ''}`,
    t('信心 {n}%', { n: r.confidence ?? 0 }),
    t('授權：{license}', { license: r.license ?? '—' }),
    r.fetched_at ? t('清單抓取：{at}', { at: r.fetched_at.slice(0, 16).replace('T', ' ') }) : '',
    r.matched ? t('命中：{m}', { m: r.matched }) : '',
  ]
    .filter(Boolean)
    .join('\n');
  const strong = (r.confidence ?? 0) >= 80;
  const cls = `inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs ${
    strong
      ? 'border-red-300 bg-red-50 text-red-800 dark:border-red-800 dark:bg-red-950/40 dark:text-red-300'
      : 'border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300'
  }`;
  const body = (
    <>
      <span className="font-medium">{r.vendor ?? r.feed_id}</span>
      <span className="opacity-70">{r.confidence ?? 0}%</span>
    </>
  );
  return r.source_url && /^https:\/\//.test(r.source_url) ? (
    <a href={r.source_url} target="_blank" rel="noreferrer noopener" title={title} className={`${cls} hover:underline`}>
      {body}
    </a>
  ) : (
    <span title={title} className={cls}>
      {body}
    </span>
  );
}

export function ReasonList({ reasons, t, max = 6 }: { reasons: Reason[]; t: TFn; max?: number }) {
  if (!reasons.length) return <span className="text-xs text-slate-400">—</span>;
  const shown = reasons.slice(0, max);
  return (
    <div className="flex flex-wrap items-center gap-1">
      {shown.map((r, i) => {
        switch (r.type) {
          case 'intel_hit':
            return <SourceBadge key={i} r={r} t={t} />;
          case 'anomaly':
            return (
              <span
                key={i}
                title={r.detail}
                className="rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-900 dark:bg-amber-900/40 dark:text-amber-200"
              >
                {anomalyLabel(t, r.kind ?? '')}
              </span>
            );
          case 'reputation':
            return (
              <span key={i} title={r.detail} className="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-800">
                {t('{provider} 名譽 {score}', { provider: r.provider ?? '', score: r.score ?? 0 })}
              </span>
            );
          case 'known_good':
            return (
              <span key={i} title={r.detail} className="rounded bg-green-50 px-1.5 py-0.5 text-xs text-green-800 dark:bg-green-950/40 dark:text-green-300">
                {t('已知良好：{list}', { list: r.list ?? '' })}
              </span>
            );
          case 'allowlisted':
            return (
              <span key={i} className="rounded bg-green-50 px-1.5 py-0.5 text-xs text-green-800 dark:bg-green-950/40 dark:text-green-300">
                {t('白名單')}
              </span>
            );
          case 'private_network':
            return (
              <span key={i} className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                {t('私有網路')}
              </span>
            );
          case 'loopback':
            return (
              <span key={i} className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                {t('本機迴路')}
              </span>
            );
          default:
            return (
              <span key={i} className="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-800">
                {r.type}
              </span>
            );
        }
      })}
      {reasons.length > max ? <span className="text-xs text-slate-500">+{reasons.length - max}</span> : null}
    </div>
  );
}
