// 網路流量與效能的頁面區塊（server component）：頻寬圖、主機流量排行、各介面、各程式、主機效能分頁。
import Link from 'next/link';
import { TimeChart } from '@/components/charts/TimeChart';
import { Badge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow } from '@/components/ui/Filters';
import { Hint } from '@/components/ui/Hint';
import { fmtBytes, fmtPct, fmtRate, since, utc } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import {
  RANGES,
  bandwidthSeries,
  hostPerfSeries,
  interfaceBreakdown,
  latestPerf,
  processTraffic,
  type HostTraffic,
  type IfaceTraffic,
  type LatestPerf,
  type PerfAlert,
  type Range,
} from '@/lib/queries/metrics';
import { toQuery } from '@/lib/queries/params';

const TABLE = 'overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900';
const HEAD = 'border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800';
const ROW = 'border-b border-slate-100 last:border-0 dark:border-slate-800';
const H2 = 'text-sm font-semibold text-slate-600 dark:text-slate-300';
const DL = 'var(--chart-1)';
const UL = 'var(--chart-2)';

export function rangeLabel(t: TFn, r: Range): string {
  return { '1h': t('1 小時'), '24h': t('24 小時'), '7d': t('7 天'), '30d': t('30 天') }[r];
}

/** 期間切換（純連結）。 */
export function RangeChips({ t, base, range, keep = {} }: { t: TFn; base: string; range: Range; keep?: Record<string, string | number | undefined> }) {
  const sep = base.includes('?') ? '&' : '?';
  return (
    <FilterRow label={t('期間')}>
      {RANGES.map((r) => (
        <FilterChip key={r} href={`${base}${toQuery({ ...keep, range: r }).replace('?', sep)}`} active={r === range}>
          {rangeLabel(t, r)}
        </FilterChip>
      ))}
    </FilterRow>
  );
}

const timeMode = (r: Range) => (r === '7d' || r === '30d' ? 'date' : 'time');

/** 下載＝藍、上傳＝橘；兩條都標名稱（不靠顏色辨識）。 */
export function BandwidthChart({ t, data, height = 180 }: { t: TFn; data: Awaited<ReturnType<typeof bandwidthSeries>>; height?: number }) {
  return (
    <TimeChart
      label={t('下載與上傳速率')}
      format="rate"
      height={height}
      timeMode={timeMode(data.range)}
      times={data.points.map((p) => p.t)}
      series={[
        { label: t('下載'), color: DL, values: data.points.map((p) => p.rx) },
        { label: t('上傳'), color: UL, values: data.points.map((p) => p.tx) },
      ]}
    />
  );
}

/** 兩段長條（下載＋上傳，中間留 2px 縫），長度對齊表格裡最大的那台。 */
function SplitBar({ rx, tx, max }: { rx: number; tx: number; max: number }) {
  const px = (v: number) => (max > 0 ? (v / max) * 140 : 0);
  return (
    <div className="flex h-2 items-center gap-[2px]" aria-hidden>
      {rx > 0 ? <div className="h-2 rounded-l" style={{ width: Math.max(2, px(rx)), background: DL }} /> : null}
      {tx > 0 ? <div className="h-2 rounded-r" style={{ width: Math.max(2, px(tx)), background: UL }} /> : null}
    </div>
  );
}

export function HostTrafficTable({ t, rows }: { t: TFn; rows: HostTraffic[] }) {
  const max24 = Math.max(0, ...rows.map((r) => r.rx24h + r.tx24h));
  const max7 = Math.max(0, ...rows.map((r) => r.rx7d + r.tx7d));
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('主機')}</th>
            <th className="px-3 py-2">{t('24 小時（下載／上傳）')}</th>
            <th className="px-3 py-2">{t('7 天（下載／上傳）')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.agentId} className={ROW}>
              <td className="px-3 py-2">
                <Link className="text-teal-700 hover:underline dark:text-teal-400" href={`/agents/${encodeURIComponent(r.agentId)}?tab=perf`}>
                  {r.hostname}
                </Link>
              </td>
              <td className="px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <SplitBar rx={r.rx24h} tx={r.tx24h} max={max24} />
                  <span className="tabular-nums text-xs">
                    ↓ {fmtBytes(r.rx24h)} · ↑ {fmtBytes(r.tx24h)}
                  </span>
                </div>
              </td>
              <td className="px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <SplitBar rx={r.rx7d} tx={r.tx7d} max={max7} />
                  <span className="tabular-nums text-xs">
                    ↓ {fmtBytes(r.rx7d)} · ↑ {fmtBytes(r.tx7d)}
                  </span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function InterfaceTable({ t, rows, showHost = true }: { t: TFn; rows: IfaceTraffic[]; showHost?: boolean }) {
  const max = Math.max(0, ...rows.map((r) => r.rx + r.tx));
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            {showHost ? <th className="px-3 py-2">{t('主機')}</th> : null}
            <th className="px-3 py-2">
              {t('網路介面')}
              <Hint text={t('網路卡或虛擬網卡（例如 Wi-Fi、乙太網路、VPN、Docker）。虛擬介面的流量其實也會經過實體網卡，所以不算進總量。')} />
            </th>
            <th className="px-3 py-2">{t('下載／上傳')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={`${r.agentId}|${r.name}`} className={ROW}>
              {showHost ? <td className="whitespace-nowrap px-3 py-2">{r.hostname}</td> : null}
              <td className="px-3 py-2">
                <span className="font-mono text-xs">{r.name}</span>{' '}
                {r.virtual ? (
                  <span title={t('虛擬介面（VPN、Docker、WSL、Hyper-V…）：不算進總量')}>
                    <Badge tone="info">{t('虛擬')}</Badge>
                  </span>
                ) : null}
              </td>
              <td className="px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <SplitBar rx={r.rx} tx={r.tx} max={max} />
                  <span className="tabular-nums text-xs">
                    ↓ {fmtBytes(r.rx)} · ↑ {fmtBytes(r.tx)}
                  </span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ProcessTrafficTable({ t, data, showHosts = true }: { t: TFn; data: Awaited<ReturnType<typeof processTraffic>>; showHosts?: boolean }) {
  const max = Math.max(0, ...data.rows.map((r) => r.rx + r.tx));
  return (
    <div className="space-y-2">
      <div className={TABLE}>
        <table className="w-full text-left text-sm">
          <thead className={HEAD}>
            <tr>
              <th className="px-3 py-2">{t('程式')}</th>
              <th className="px-3 py-2">{t('下載／上傳')}</th>
              {showHosts ? <th className="px-3 py-2">{t('主機')}</th> : null}
            </tr>
          </thead>
          <tbody>
            {data.rows.map((r) => (
              <tr key={r.name} className={ROW}>
                <td className="px-3 py-2">{r.name}</td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SplitBar rx={r.rx} tx={r.tx} max={max} />
                    <span className="tabular-nums text-xs">
                      ↓ {fmtBytes(r.rx)} · ↑ {fmtBytes(r.tx)}
                    </span>
                  </div>
                </td>
                {showHosts ? <td className="px-3 py-2 tabular-nums">{r.hosts}</td> : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data.hostsWithData < data.hostsTotal ? (
        <p className="text-xs text-slate-500">
          {t('{n} 台主機量不到各程式的流量（Linux 需要 eBPF；Windows 要以系統管理員執行，例如裝成系統服務），只列出量得到的主機。', {
            n: data.hostsTotal - data.hostsWithData,
          })}
        </p>
      ) : null}
    </div>
  );
}

/** 流量頁最上面的區塊：所有主機的頻寬、排行、各介面、各程式。 */
export async function FleetTrafficSection({ t, range, agentId, ranking = [] }: { t: TFn; range: Range; agentId?: string; ranking?: HostTraffic[] }) {
  const [bw, ifaces, procs] = await Promise.all([bandwidthSeries(range, agentId), interfaceBreakdown(range, agentId, 30), processTraffic(range, agentId, 15)]);
  if (!bw.hasData && !ranking.length) {
    return (
      <EmptyState title={t('還沒有流量統計')}>
        {t('主機的 ai-security-monitor（0.3.0 之後的版本）執行 watch 或背景服務時，每分鐘會回報各網路介面的上傳／下載量。')}
      </EmptyState>
    );
  }
  return (
    <div className="space-y-4">
      <Card
        title={
          <span className="flex flex-wrap items-center justify-between gap-2">
            <span>
              {agentId ? t('頻寬') : t('頻寬（所有主機加總）')}
              <Hint text={t('每台主機每分鐘回報實體網卡收到（下載）與送出（上傳）的位元組；圖上是每段時間的平均速度。')} />
            </span>
            <span className="text-xs font-normal text-slate-500">
              {t('{range}合計：下載 {rx}、上傳 {tx}', { range: rangeLabel(t, range), rx: fmtBytes(bw.totalRx), tx: fmtBytes(bw.totalTx) })}
            </span>
          </span>
        }
      >
        <BandwidthChart t={t} data={bw} />
      </Card>
      {!agentId && ranking.length ? (
        <section className="space-y-2">
          <h2 className={H2}>{t('流量最多的主機')}</h2>
          <HostTrafficTable t={t} rows={ranking} />
        </section>
      ) : null}
      <div className="grid gap-4 xl:grid-cols-2">
        {ifaces.length ? (
          <section className="space-y-2">
            <h2 className={H2}>{t('各網路介面（{range}）', { range: rangeLabel(t, range) })}</h2>
            <InterfaceTable t={t} rows={ifaces} showHost={!agentId} />
          </section>
        ) : null}
        <section className="space-y-2">
          <h2 className={H2}>
            {t('各程式的流量（{range}）', { range: rangeLabel(t, range) })}
            <Hint text={t('哪個程式收送了多少資料。Windows 要以系統管理員執行（背景服務就是），macOS 用系統內建的 nettop；Linux 量不到，請看下方「各行程目前的連線」。')} />
          </h2>
          {procs.rows.length ? (
            <ProcessTrafficTable t={t} data={procs} showHosts={!agentId} />
          ) : (
            <p className="rounded-xl border border-dashed border-slate-300 p-4 text-sm text-slate-500 dark:border-slate-700">
              {t('這段期間沒有主機回報各程式的流量（Linux 需要 eBPF；Windows 要以系統管理員執行）。可以改看下方各行程的連線數。')}
            </p>
          )}
        </section>
      </div>
    </div>
  );
}

function Meter({ value, label }: { value: number | null; label: string }) {
  const v = value == null ? 0 : Math.max(0, Math.min(100, value));
  const hot = (value ?? 0) >= 90;
  return (
    <div role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={value == null ? undefined : Math.round(v)} className="h-2 w-full rounded bg-slate-200 dark:bg-slate-800">
      <div className={`h-2 rounded ${hot ? 'bg-sev-high' : ''}`} style={{ width: `${v}%`, ...(hot ? {} : { background: DL }) }} />
    </div>
  );
}

function PerfStat({ label, value, sub, pct, hint }: { label: string; value: string; sub?: string; pct?: number | null; hint?: string }) {
  return (
    <Card>
      <div className="text-xs text-slate-500">
        {label}
        {hint ? <Hint text={hint} /> : null}
      </div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {pct !== undefined ? (
        <div className="mt-2">
          <Meter value={pct} label={label} />
        </div>
      ) : null}
      {sub ? <div className="mt-1 text-xs text-slate-500">{sub}</div> : null}
    </Card>
  );
}

function TopProcs({ t, title, rows, by }: { t: TFn; title: string; rows: LatestPerf['topCpu']; by: 'cpu' | 'mem' }) {
  return (
    <Card title={title}>
      {rows.length ? (
        <table className="w-full text-left text-sm">
          <thead className={HEAD}>
            <tr>
              <th className="py-1.5 pr-2">{t('程式')}</th>
              <th className="py-1.5 pr-2">pid</th>
              <th className={`py-1.5 pr-2 ${by === 'cpu' ? 'font-semibold' : ''}`}>CPU</th>
              <th className={`py-1.5 ${by === 'mem' ? 'font-semibold' : ''}`}>
                {t('記憶體')}
                <Hint text={t('程式實際占用的實體記憶體（RSS）。同名的多個行程（例如瀏覽器）合併計算。')} />
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.name} className={ROW}>
                <td className="py-1.5 pr-2">
                  {p.name}
                  {p.count > 1 ? <span className="ml-1 text-xs text-slate-500">×{p.count}</span> : null}
                </td>
                <td className="py-1.5 pr-2 font-mono text-xs text-slate-500">{p.pid ?? '—'}</td>
                <td className="py-1.5 pr-2 tabular-nums">{p.cpu.toFixed(1)}%</td>
                <td className="py-1.5 tabular-nums">{fmtBytes(p.rss)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="text-sm text-slate-500">—</p>
      )}
    </Card>
  );
}

/** 「未開啟」的說明（主機自己決定；Hub 不能從遠端開）。 */
export function PerfOffNotice({ t, never }: { t: TFn; never: boolean }) {
  return (
    <EmptyState title={never ? t('這台主機還沒有回報效能資料') : t('效能蒐集：未開啟')}>
      <p>
        {never
          ? t('需要 0.3.0 之後版本的 ai-security-monitor，並在這台電腦上開啟效能蒐集。')
          : t('這台電腦沒有開啟效能蒐集，所以這裡只有網路流量。要不要蒐集 CPU、記憶體、磁碟由電腦本身決定，Hub 無法從遠端開啟。')}
      </p>
      <p className="mt-2">{t('在那台電腦上開啟（任選一種）：')}</p>
      <ul className="mx-auto mt-1 max-w-xl list-disc space-y-1 pl-5 text-left">
        <li>{t('桌面版：設定 →「蒐集這台電腦的效能（CPU、記憶體、磁碟）」')}</li>
        <li>
          {t('命令列：')}
          <code className="rounded bg-slate-100 px-1 font-mono text-xs dark:bg-slate-800">ai-security-monitor config set metrics.performance true</code>
        </li>
      </ul>
      <p className="mt-2 text-xs">{t('資料只會送到這台電腦加入的 Hub。背景服務每分鐘會重讀設定，不用重新啟動。')}</p>
    </EmptyState>
  );
}

/** 主機頁「效能」分頁。 */
export async function HostPerfView({ t, agentId, perfEnabled, range, base }: { t: TFn; agentId: string; perfEnabled: boolean | null; range: Range; base: string }) {
  const [series, latest] = await Promise.all([hostPerfSeries(agentId, range), perfEnabled ? latestPerf(agentId) : Promise.resolve(null)]);
  const times = series.points.map((p) => p.t);
  const tm = timeMode(range);
  const net = (
    <Card title={t('網路速率')}>
      <TimeChart
        label={t('下載與上傳速率')}
        format="rate"
        timeMode={tm}
        times={times}
        series={[
          { label: t('下載'), color: DL, values: series.points.map((p) => p.rx) },
          { label: t('上傳'), color: UL, values: series.points.map((p) => p.tx) },
        ]}
        emptyText={t('這段期間沒有流量資料')}
      />
    </Card>
  );
  const chips = <RangeChips t={t} base={base} range={range} keep={{ tab: 'perf' }} />;
  if (!perfEnabled || !series.hasPerf) {
    return (
      <div className="space-y-4">
        {chips}
        <PerfOffNotice t={t} never={perfEnabled === null} />
        {net}
      </div>
    );
  }
  const memPct = latest?.memTotal ? ((latest.memUsed ?? 0) / latest.memTotal) * 100 : null;
  const diskMax = latest?.disks.length ? Math.max(...latest.disks.map((d) => (d.total ? (d.used / d.total) * 100 : 0))) : null;
  const ioRate = (v: number | null | undefined) => (v == null || !latest ? null : v / Math.max(1, latest.intervalS));
  const up = latest?.uptimeS ?? null;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {chips}
        {latest ? <span className="text-xs text-slate-500">{t('最新樣本 {at}（{ago}）', { at: utc(latest.at), ago: since(latest.at, t) })}</span> : null}
      </div>
      {latest ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <PerfStat label="CPU" value={fmtPct(latest.cpuPct)} pct={latest.cpuPct} sub={t('{n} 個邏輯核心{load}', { n: latest.cpuCores ?? '—', load: latest.load1 != null ? t('，負載 {l}', { l: latest.load1.toFixed(2) }) : '' })} hint={t('整台電腦的處理器使用率（所有核心平均）。負載是等著用 CPU 的工作數，只有 Linux／macOS 有。')} />
          <PerfStat label={t('記憶體')} value={fmtPct(memPct)} pct={memPct} sub={`${fmtBytes(latest.memUsed)}／${fmtBytes(latest.memTotal)}${latest.swapTotal ? t('，置換 {u}／{tot}', { u: fmtBytes(latest.swapUsed), tot: fmtBytes(latest.swapTotal) }) : ''}`} hint={t('已用＝總量減掉可立即使用的部分（可回收的快取不算已用）。置換是記憶體不夠時暫存到磁碟的空間。')} />
          <PerfStat label={t('磁碟（最滿的磁碟區）')} value={fmtPct(diskMax)} pct={diskMax} sub={t('讀 {r}、寫 {w}', { r: fmtRate(ioRate(latest.diskRead)), w: fmtRate(ioRate(latest.diskWrite)) })} hint={t('各磁碟區裡用得最滿的那個；讀寫是最近一分鐘的平均速度。')} />
          <PerfStat
            label={latest.battery ? t('電池') : t('開機時間')}
            value={latest.battery ? `${latest.battery.percent}%` : up != null ? t('{d} 天 {h} 小時', { d: Math.floor(up / 86_400), h: Math.floor((up % 86_400) / 3600) }) : '—'}
            pct={latest.battery ? latest.battery.percent : undefined}
            sub={latest.battery ? (latest.battery.charging ? t('充電中') : latest.battery.plugged ? t('接著電源') : t('使用電池')) : t('距離上次開機')}
          />
        </div>
      ) : null}
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={t('CPU 使用率')}>
          <TimeChart
            label={t('CPU 使用率')}
            format="pct"
            timeMode={tm}
            times={times}
            series={[
              { label: t('平均'), color: DL, values: series.points.map((p) => p.cpu) },
              { label: t('最高'), color: UL, values: series.points.map((p) => p.cpuMax), dashed: true },
            ]}
          />
        </Card>
        <Card title={t('記憶體使用率')}>
          <TimeChart label={t('記憶體使用率')} format="pct" timeMode={tm} times={times} series={[{ label: t('記憶體'), color: DL, values: series.points.map((p) => p.memPct) }]} />
        </Card>
        <Card title={t('磁碟用量（最滿的磁碟區）')}>
          <TimeChart label={t('磁碟用量')} format="pct" timeMode={tm} times={times} series={[{ label: t('磁碟'), color: DL, values: series.points.map((p) => p.diskPct) }]} />
        </Card>
        <Card title={t('磁碟讀寫')}>
          <TimeChart
            label={t('磁碟讀寫速度')}
            format="rate"
            timeMode={tm}
            times={times}
            series={[
              { label: t('讀取'), color: DL, values: series.points.map((p) => p.diskRead) },
              { label: t('寫入'), color: UL, values: series.points.map((p) => p.diskWrite) },
            ]}
          />
        </Card>
        {net}
        {series.points.some((p) => p.battery != null) ? (
          <Card title={t('電池電量')}>
            <TimeChart label={t('電池電量')} format="pct" timeMode={tm} times={times} series={[{ label: t('電池'), color: DL, values: series.points.map((p) => p.battery) }]} />
          </Card>
        ) : null}
      </div>
      {latest ? (
        <>
          <div className="grid gap-4 xl:grid-cols-2">
            <TopProcs t={t} title={t('最吃 CPU 的程式')} rows={latest.topCpu} by="cpu" />
            <TopProcs t={t} title={t('最吃記憶體的程式')} rows={latest.topMem} by="mem" />
          </div>
          <Card title={t('各磁碟區')}>
            <ul className="space-y-2 text-sm">
              {latest.disks.map((d) => {
                const pct = d.total ? (d.used / d.total) * 100 : null;
                return (
                  <li key={d.mount} className="grid grid-cols-[minmax(6rem,12rem)_1fr_auto] items-center gap-3">
                    <span className="truncate font-mono text-xs" title={d.mount}>
                      {d.mount}
                      {d.fs ? <span className="ml-1 text-slate-500">{d.fs}</span> : null}
                    </span>
                    <Meter value={pct} label={d.mount} />
                    <span className={`tabular-nums text-xs ${(pct ?? 0) >= 90 ? 'font-semibold text-sev-high' : 'text-slate-500'}`}>
                      {fmtBytes(d.used)}／{fmtBytes(d.total)}（{fmtPct(pct)}）
                    </span>
                  </li>
                );
              })}
            </ul>
          </Card>
        </>
      ) : null}
    </div>
  );
}

/** 總覽：資源吃緊的主機（最新樣本 CPU／記憶體／磁碟 ≥ 90%）。 */
export function PerfAlertsCard({ t, alerts, perfHosts, linkable }: { t: TFn; alerts: PerfAlert[]; perfHosts: number; linkable: boolean }) {
  const what = { cpu: 'CPU', mem: t('記憶體'), disk: t('磁碟') } as const;
  return (
    <Card
      title={
        <>
          {t('資源吃緊的主機')}
          <Hint text={t('只看有開啟效能蒐集的主機：最新一分鐘的 CPU、記憶體或任一磁碟用量到 90% 以上。磁碟滿或 CPU 連續 15 分鐘滿載也會列成「低」的待處理問題。')} />
        </>
      }
    >
      {alerts.length ? (
        <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
          {alerts.slice(0, 8).map((a) => (
            <li key={a.agentId} className="flex flex-wrap items-center gap-2 py-2">
              {linkable ? (
                <Link className="font-medium text-teal-700 hover:underline dark:text-teal-400" href={`/agents/${encodeURIComponent(a.agentId)}?tab=perf`}>
                  {a.hostname}
                </Link>
              ) : (
                <span className="font-medium">{a.hostname}</span>
              )}
              {a.reasons.map((r) => (
                <Badge key={r} tone="warn">
                  {what[r]} {fmtPct(r === 'cpu' ? a.cpu : r === 'mem' ? a.memPct : a.diskPct)}
                </Badge>
              ))}
              <span className="ml-auto text-xs text-slate-500">{since(a.at, t)}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-slate-500">
          {perfHosts
            ? t('{n} 台開啟效能蒐集的主機目前都正常。', { n: perfHosts })
            : t('還沒有主機開啟效能蒐集（由各台電腦自己在桌面版設定或命令列開啟）。')}
        </p>
      )}
    </Card>
  );
}
