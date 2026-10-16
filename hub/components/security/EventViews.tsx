// 當機與資安事件、流量目的地的表格（server component，只吃 t）。
import Link from 'next/link';
import { DirectionBadge, SourceBadge, VerdictChip } from '@/components/security/Verdict';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import type { recentCrashes, securityHits } from '@/lib/queries/events';
import type { processActivity, topDestinations } from '@/lib/queries/traffic';

export function crashKindLabel(t: TFn, k: string): string {
  return (
    {
      bugcheck: t('藍屏'),
      unexpected_shutdown: t('非預期關機'),
      app_crash: t('程式當掉'),
      app_hang: t('程式沒回應'),
      service_fail: t('服務失敗'),
      disk_error: t('磁碟錯誤'),
      whea_hardware: t('硬體錯誤'),
      update_failure: t('更新失敗'),
      gpu_reset: t('顯示卡重設'),
      low_memory: t('記憶體不足'),
      kernel_panic: 'kernel panic',
      oom: 'OOM',
      oops: 'kernel oops',
      segfault: 'segfault',
    } as Record<string, string>
  )[k] ?? k;
}

export function securityRuleLabel(t: TFn, r: string): string {
  return (
    {
      failed_logon_burst: t('暴力破解'),
      remote_logon: t('公網遠端登入'),
      admin_member_added: t('加入管理員群組'),
      group_member_added: t('加入群組'),
      user_created: t('新帳號'),
      user_enabled: t('啟用帳號'),
      service_installed: t('新服務'),
      task_created: t('新排程'),
      audit_log_cleared: t('稽核紀錄被清除'),
      log_cleared: t('事件記錄被清除'),
      defender_detection: t('Defender 偵測'),
      defender_disabled: t('Defender 被關閉'),
    } as Record<string, string>
  )[r] ?? r;
}

const TABLE = 'overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900';
const HEAD = 'border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800';
const ROW = 'border-b border-slate-100 align-top last:border-0 dark:border-slate-800';

type Crash = Awaited<ReturnType<typeof recentCrashes>>[number];

export function CrashTable({ t, rows, showHost = true }: { t: TFn; rows: Crash[]; showHost?: boolean }) {
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('時間')}</th>
            <th className="px-3 py-2">{t('類型')}</th>
            {showHost ? <th className="px-3 py-2">{t('主機')}</th> : null}
            <th className="px-3 py-2">{t('代碼／名稱')}</th>
            <th className="px-3 py-2">{t('模組／程式')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => {
            const d = c.details as { likely_causes?: string[]; remediation?: string | null };
            return (
              <tr key={c.id} className={ROW}>
                <td className="px-3 py-2 whitespace-nowrap text-slate-500">{since(c.time, t)}</td>
                <td className="px-3 py-2 whitespace-nowrap">{crashKindLabel(t, c.kind)}</td>
                {showHost ? (
                  <td className="px-3 py-2 whitespace-nowrap">
                    <Link className="hover:underline" href={`/agents/${encodeURIComponent(c.agentId)}?tab=events`}>
                      {c.hostname}
                    </Link>
                  </td>
                ) : null}
                <td className="px-3 py-2">
                  <div className="font-mono text-xs">{c.code ?? ''}</div>
                  <div>{c.name ?? ''}</div>
                  {d.likely_causes?.length ? (
                    <details className="mt-1 text-xs text-slate-600 dark:text-slate-300">
                      <summary className="cursor-pointer text-slate-500">{t('可能原因與處置')}</summary>
                      <ul className="ml-4 list-disc">
                        {d.likely_causes.map((x, i) => (
                          <li key={i}>{x}</li>
                        ))}
                      </ul>
                      {d.remediation ? <p className="mt-1">→ {d.remediation}</p> : null}
                    </details>
                  ) : null}
                </td>
                <td className="px-3 py-2 text-xs">{c.module ?? c.process ?? ''}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

type Hit = Awaited<ReturnType<typeof securityHits>>[number];

const SEV_TONE: Record<string, string> = {
  critical: 'bg-sev-critical text-white',
  high: 'bg-sev-high text-white',
  medium: 'bg-sev-medium text-white',
  low: 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200',
  info: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
};

export function SecurityTable({ t, rows, showHost = true }: { t: TFn; rows: Hit[]; showHost?: boolean }) {
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('嚴重度')}</th>
            <th className="px-3 py-2">{t('類型')}</th>
            {showHost ? <th className="px-3 py-2">{t('主機')}</th> : null}
            <th className="px-3 py-2">{t('來源／帳號')}</th>
            <th className="px-3 py-2">{t('說明')}</th>
            <th className="px-3 py-2">{t('次數')}</th>
            <th className="px-3 py-2">{t('最後')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((h) => (
            <tr key={h.id} className={ROW}>
              <td className="px-3 py-2">
                <span className={`rounded px-1.5 py-0.5 text-xs ${SEV_TONE[h.severity] ?? SEV_TONE.info}`}>{h.severity}</span>
              </td>
              <td className="px-3 py-2 whitespace-nowrap">{securityRuleLabel(t, h.rule)}</td>
              {showHost ? <td className="px-3 py-2 whitespace-nowrap">{h.hostname}</td> : null}
              <td className="px-3 py-2 font-mono text-xs">
                {[h.sourceIp, h.userName].filter(Boolean).join(' · ')}
                {Array.isArray(h.intel) && h.intel.length ? (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {(h.intel as { feed_id: string; vendor: string; confidence: number; source_url: string }[]).map((x, i) => (
                      <SourceBadge key={i} r={{ type: 'intel_hit', ...x }} t={t} />
                    ))}
                  </div>
                ) : null}
              </td>
              <td className="px-3 py-2 text-xs">{h.detail}</td>
              <td className="px-3 py-2 tabular-nums">{h.count}</td>
              <td className="px-3 py-2 whitespace-nowrap text-slate-500">{since(h.lastAt, t)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type Dest = Awaited<ReturnType<typeof topDestinations>>[number];

export function DestinationTable({ t, rows, showHost = true }: { t: TFn; rows: Dest[]; showHost?: boolean }) {
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('判定')}</th>
            <th className="px-3 py-2">{t('方向')}</th>
            <th className="px-3 py-2">{t('遠端')}</th>
            {showHost ? <th className="px-3 py-2">{t('主機')}</th> : null}
            <th className="px-3 py-2">{t('行程')}</th>
            <th className="px-3 py-2">{t('國家／組織')}</th>
            <th className="px-3 py-2">{t('看到次數')}</th>
            <th className="px-3 py-2">{t('最後')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((d) => (
            <tr key={`${d.agentId}-${d.remoteIp}-${d.remotePort}-${d.direction}`} className={ROW}>
              <td className="px-3 py-2">
                <VerdictChip verdict={d.worstVerdict} t={t} />
              </td>
              <td className="px-3 py-2">
                <DirectionBadge direction={d.direction} t={t} />
              </td>
              <td className="px-3 py-2 font-mono text-xs">
                <Link className="hover:underline" href={`/intel?q=${encodeURIComponent(d.remoteIp)}`}>
                  {d.remoteIp}:{d.remotePort}
                </Link>
              </td>
              {showHost ? <td className="px-3 py-2 whitespace-nowrap">{d.hostname}</td> : null}
              <td className="px-3 py-2 text-xs">{d.processName ?? '—'}</td>
              <td className="px-3 py-2 text-xs">
                {d.country ?? ''} {d.org ? <span className="text-slate-500">{d.org}</span> : null}
              </td>
              <td className="px-3 py-2 tabular-nums">{d.seenCount}</td>
              <td className="px-3 py-2 whitespace-nowrap text-slate-500">{since(d.lastSeenAt, t)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type Proc = Awaited<ReturnType<typeof processActivity>>[number];

export function ProcessTable({ t, rows, showHosts = true }: { t: TFn; rows: Proc[]; showHosts?: boolean }) {
  const max = Math.max(1, ...rows.map((r) => r.conns));
  return (
    <div className={TABLE}>
      <table className="w-full text-left text-sm">
        <thead className={HEAD}>
          <tr>
            <th className="px-3 py-2">{t('行程')}</th>
            <th className="px-3 py-2">{t('連線')}</th>
            <th className="px-3 py-2">{t('遠端數')}</th>
            {showHosts ? <th className="px-3 py-2">{t('主機')}</th> : null}
            <th className="px-3 py-2">{t('可疑／危險')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p) => (
            <tr key={p.process} className={ROW}>
              <td className="px-3 py-2">{p.process === '?' ? <span className="text-slate-500">{t('未知行程')}</span> : p.process}</td>
              <td className="px-3 py-2">
                <div className="flex items-center gap-2">
                  <div className="h-2 rounded bg-teal-600" style={{ width: `${Math.max(4, (p.conns / max) * 120)}px` }} aria-hidden />
                  <span className="tabular-nums">{p.conns}</span>
                </div>
              </td>
              <td className="px-3 py-2 tabular-nums">{p.remotes}</td>
              {showHosts ? <td className="px-3 py-2 tabular-nums">{p.hosts}</td> : null}
              <td className={`px-3 py-2 tabular-nums ${p.risky ? 'font-semibold text-verdict-dangerous' : 'text-slate-400'}`}>{p.risky}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
