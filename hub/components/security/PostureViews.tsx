// 漏洞與硬化的表格與徽章（server component，只吃 t）。
import Link from 'next/link';
import { Badge } from '@/components/ui/Badge';
import { sevLabel } from '@/components/ui/Severity';
import type { TFn } from '@/lib/i18n/core';
import type { AppHit, HostRef, Outcome, VulnSummary } from '@/lib/queries/posture';
import { httpsHref } from '@/lib/links';

const TABLE = 'overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900';
const HEAD = 'border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap';
const ROW = 'border-b border-slate-100 align-top last:border-0 dark:border-slate-800';
const LINK = 'text-teal-700 hover:underline dark:text-teal-400';

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEV_DOT: Record<Sev, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
};

export function SevTag({ t, s }: { t: TFn; s: Sev }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span className={`h-2.5 w-2.5 rounded-full ${SEV_DOT[s]}`} aria-hidden />
      {sevLabel(t, s)}
    </span>
  );
}

export function SupportBadge({ t, status }: { t: TFn; status: string | undefined }) {
  if (status === 'supported') return <Badge tone="ok">{t('支援中')}</Badge>;
  if (status === 'ending_soon') return <Badge tone="warn">{t('即將停止支援')}</Badge>;
  if (status === 'eol') return <Badge tone="bad">{t('已停止支援')}</Badge>;
  return <Badge>{t('未知')}</Badge>;
}

export function ResultBadge({ t, r }: { t: TFn; r: Outcome['result'] }) {
  if (r === 'pass') return <Badge tone="ok">{t('通過')}</Badge>;
  if (r === 'fail') return <Badge tone="bad">{t('未通過')}</Badge>;
  if (r === 'not_applicable') return <Badge>{t('不適用')}</Badge>;
  return <Badge tone="warn">{t('錯誤')}</Badge>;
}

function CveLinks({ cves, kev }: { cves: string[]; kev: string[] }) {
  return (
    <span className="flex flex-wrap gap-x-2 gap-y-0.5">
      {cves.slice(0, 6).map((c) => (
        <a key={c} className={`${LINK} font-mono text-xs`} href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`} target="_blank" rel="noreferrer">
          {c}
          {kev.includes(c) ? <span className="ml-1 rounded bg-red-600 px-1 text-[10px] font-semibold text-white">KEV</span> : null}
        </a>
      ))}
      {cves.length > 6 ? <span className="text-xs text-slate-500">+{cves.length - 6}</span> : null}
    </span>
  );
}

function HostLinks({ hosts, tab }: { hosts: HostRef[]; tab: string }) {
  return (
    <span className="flex flex-wrap gap-x-2">
      {hosts.slice(0, 8).map((h) => (
        <Link key={h.agentId} className="hover:underline" href={`/agents/${encodeURIComponent(h.agentId)}?tab=${tab}`}>
          {h.hostname}
        </Link>
      ))}
      {hosts.length > 8 ? <span className="text-slate-500">+{hosts.length - 8}</span> : null}
    </span>
  );
}

/** 單台主機的已知漏洞軟體。 */
export function AppHitsTable({ t, hits }: { t: TFn; hits: AppHit[] }) {
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('嚴重度')}</th>
            <th className="px-3 py-2">{t('軟體')}</th>
            <th className="px-3 py-2">{t('已安裝')}</th>
            <th className="px-3 py-2">{t('修正版')}</th>
            <th className="px-3 py-2">CVE</th>
          </tr>
        </thead>
        <tbody>
          {hits.map((h) => (
            <tr key={`${h.rule_id}|${h.installed}`} className={ROW}>
              <td className="px-3 py-2">
                <SevTag t={t} s={h.severity} />
              </td>
              <td className="px-3 py-2">
                <div>{h.installed_name}</div>
                {h.summary ? (
                  <details className="mt-1 text-xs text-slate-600 dark:text-slate-300">
                    <summary className="cursor-pointer text-slate-500">{t('說明與處置')}</summary>
                    <p>{h.summary}</p>
                    {h.fix ? <p className="mt-1">→ {h.fix}</p> : null}
                  </details>
                ) : null}
              </td>
              <td className="px-3 py-2 font-mono text-xs">{h.installed}</td>
              <td className="px-3 py-2 font-mono text-xs">{h.fixed}</td>
              <td className="px-3 py-2">{h.eol ? <Badge tone="warn">{t('停止支援')}</Badge> : <CveLinks cves={h.cves} kev={h.kev} />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** 車隊：已知漏洞軟體依規則彙總。 */
export function FleetAppsTable({ t, rows }: { t: TFn; rows: { hit: AppHit; hosts: (HostRef & { installed: string })[] }[] }) {
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('嚴重度')}</th>
            <th className="px-3 py-2">{t('軟體')}</th>
            <th className="px-3 py-2">{t('修正版')}</th>
            <th className="px-3 py-2">CVE</th>
            <th className="px-3 py-2">{t('主機')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ hit, hosts }) => (
            <tr key={hit.rule_id} className={ROW}>
              <td className="px-3 py-2">
                <SevTag t={t} s={hit.severity} />
              </td>
              <td className="px-3 py-2">
                <div>{hit.app}</div>
                {hit.fix ? <div className="text-xs text-slate-500">→ {hit.fix}</div> : null}
              </td>
              <td className="px-3 py-2 font-mono text-xs">{hit.fixed}</td>
              <td className="px-3 py-2">{hit.eol ? <Badge tone="warn">{t('停止支援')}</Badge> : <CveLinks cves={hit.cves} kev={hit.kev} />}</td>
              <td className="px-3 py-2">
                <div className="text-xs text-slate-500">{t('{n} 台主機', { n: hosts.length })}</div>
                <HostLinks hosts={hosts} tab="vulns" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** 單台主機的 OSV 套件結果。 */
export function OsvTable({ t, osv }: { t: TFn; osv: NonNullable<VulnSummary['osv']> }) {
  const eco = encodeURIComponent(osv.ecosystem);
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('嚴重度')}</th>
            <th className="px-3 py-2">{t('套件')}</th>
            <th className="px-3 py-2">{t('版本')}</th>
            <th className="px-3 py-2">{t('漏洞數')}</th>
            <th className="px-3 py-2">CVE</th>
          </tr>
        </thead>
        <tbody>
          {osv.packages.slice(0, 100).map((p) => (
            <tr key={p.name} className={ROW}>
              <td className="px-3 py-2">
                <SevTag t={t} s={p.severity} />
              </td>
              <td className="px-3 py-2">
                <a className={LINK} href={`https://osv.dev/list?ecosystem=${eco}&q=${encodeURIComponent(p.name)}`} target="_blank" rel="noreferrer">
                  {p.name}
                </a>
                {p.summary ? <div className="text-xs text-slate-500">{p.summary}</div> : null}
              </td>
              <td className="px-3 py-2 font-mono text-xs">{p.version}</td>
              <td className="px-3 py-2 tabular-nums">{p.ids.length}</td>
              <td className="px-3 py-2">
                <CveLinks cves={p.cves} kev={p.kev} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** 單台主機的硬化檢查結果。 */
export function HardeningTable({ t, rows }: { t: TFn; rows: Outcome[] }) {
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('結果')}</th>
            <th className="px-3 py-2">{t('嚴重度')}</th>
            <th className="px-3 py-2">{t('檢查')}</th>
            <th className="px-3 py-2">{t('目前')}</th>
            <th className="px-3 py-2">{t('期望')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((o) => (
            <tr key={o.id} className={ROW}>
              <td className="px-3 py-2">
                <ResultBadge t={t} r={o.result} />
              </td>
              <td className="px-3 py-2">
                <SevTag t={t} s={o.severity} />
              </td>
              <td className="px-3 py-2">
                <div>{o.title}</div>
                <div className="font-mono text-[11px] text-slate-400">{o.id}</div>
                <WhyAndFix t={t} o={o} />
              </td>
              <td className="px-3 py-2 text-xs">{o.observed || <span className="text-slate-400">{o.note ?? '—'}</span>}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-500">{o.expected}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function WhyAndFix({ t, o }: { t: TFn; o: Outcome }) {
  if (!o.rationale && !o.remediation) return null;
  return (
    <details className="mt-1 text-xs text-slate-600 dark:text-slate-300">
      <summary className="cursor-pointer text-slate-500">{t('為什麼與怎麼修')}</summary>
      {o.rationale ? <p>{o.rationale}</p> : null}
      {o.remediation ? <p className="mt-1">→ {o.remediation}</p> : null}
      <p className="mt-1 flex flex-wrap gap-x-2">
        {o.references.map((u) => (
          <a key={u} className={LINK} href={httpsHref(u)} target="_blank" rel="noreferrer">
            {hostOf(u)}
          </a>
        ))}
      </p>
    </details>
  );
}

/** 車隊：最常沒通過的硬化檢查。 */
export function FleetFailedTable({ t, rows }: { t: TFn; rows: { check: Outcome; hosts: HostRef[]; checked: number }[] }) {
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('嚴重度')}</th>
            <th className="px-3 py-2">{t('檢查')}</th>
            <th className="px-3 py-2">{t('未通過')}</th>
            <th className="px-3 py-2">{t('主機')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ check, hosts, checked }) => (
            <tr key={check.id} className={ROW}>
              <td className="px-3 py-2">
                <SevTag t={t} s={check.severity} />
              </td>
              <td className="px-3 py-2">
                <div>{check.title}</div>
                {check.remediation ? <div className="text-xs text-slate-500">→ {check.remediation}</div> : null}
              </td>
              <td className="px-3 py-2 whitespace-nowrap tabular-nums">
                {hosts.length} / {checked}
              </td>
              <td className="px-3 py-2">
                <HostLinks hosts={hosts} tab="hardening" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function hostOf(u: string): string {
  try {
    return new URL(u).hostname.replace(/^www\./, '');
  } catch {
    return u;
  }
}

/** 分數趨勢（純 SVG 折線，最舊在左）。 */
export function ScoreTrend({ t, points }: { t: TFn; points: { at: Date; overall: number; vulns?: number; hardening?: number }[] }) {
  if (points.length < 2) return <p className="text-sm text-slate-500">{t('至少要兩份報告才畫得出趨勢。')}</p>;
  const W = 600;
  const H = 120;
  const x = (i: number) => (i / (points.length - 1)) * (W - 8) + 4;
  const y = (v: number) => H - 4 - (Math.max(0, Math.min(100, v)) / 100) * (H - 8);
  const line = (pick: (p: (typeof points)[number]) => number | undefined) =>
    points
      .map((p, i) => [i, pick(p)] as const)
      .filter(([, v]) => v != null)
      .map(([i, v]) => `${x(i).toFixed(1)},${y(v as number).toFixed(1)}`)
      .join(' ');
  const series = [
    { key: 'overall', label: t('總分'), cls: 'stroke-teal-600', dot: 'bg-teal-600', pts: line((p) => p.overall) },
    { key: 'vulns', label: t('漏洞'), cls: 'stroke-amber-500', dot: 'bg-amber-500', pts: line((p) => p.vulns) },
    { key: 'hardening', label: t('硬化'), cls: 'stroke-sky-500', dot: 'bg-sky-500', pts: line((p) => p.hardening) },
  ];
  return (
    <figure>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-28 w-full" role="img" aria-label={t('分數趨勢')}>
        {[25, 50, 75].map((g) => (
          <line key={g} x1="0" x2={W} y1={y(g)} y2={y(g)} className="stroke-slate-200 dark:stroke-slate-800" strokeWidth="1" />
        ))}
        {series.map((s) => (s.pts ? <polyline key={s.key} points={s.pts} fill="none" strokeWidth="2" className={s.cls} vectorEffect="non-scaling-stroke" /> : null))}
      </svg>
      <figcaption className="mt-1 flex flex-wrap gap-3 text-xs text-slate-500">
        {series.map((s) => (
          <span key={s.key} className="inline-flex items-center gap-1">
            <span className={`inline-block h-0.5 w-4 ${s.dot}`} aria-hidden />
            {s.label}
          </span>
        ))}
      </figcaption>
    </figure>
  );
}
