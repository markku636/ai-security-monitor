// 攻擊手法總覽：待處理的問題對應到 MITRE ATT&CK 的哪些手法（戰術欄 × 技術格），以及法規控制項。點格子＝問題頁篩選。
import Link from 'next/link';
import { controlLabel } from '@/components/security/AttackTags';
import { Card } from '@/components/ui/Card';
import { HostFilter } from '@/components/ui/HostFilter';
import { Tooltip } from '@/components/ui/Tooltip';
import { CONTROLS, FRAMEWORKS, TACTICS, TECHNIQUES, techniqueUrl } from '@/lib/attack/catalog';
import { requireAdmin } from '@/lib/auth/require';
import { langOf } from '@/lib/i18n/core';
import { getT } from '@/lib/i18n/server';
import { ATTACK_WINDOWS, attackSummary, type AttackWindow } from '@/lib/queries/attack';
import { strParam, toQuery } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

type Params = Record<string, string | string[] | undefined>;

function heat(n: number): string {
  if (!n) return 'border-slate-200 text-slate-400 dark:border-slate-800 dark:text-slate-500';
  if (n >= 10) return 'border-red-400 bg-red-50 text-red-900 dark:border-red-700 dark:bg-red-950/50 dark:text-red-200';
  if (n >= 3) return 'border-orange-300 bg-orange-50 text-orange-900 dark:border-orange-700 dark:bg-orange-950/40 dark:text-orange-200';
  return 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200';
}

export default async function MitrePage({ searchParams }: { searchParams: Promise<Params> }) {
  await requireAdmin();
  const { t } = await getT();
  const en = langOf(t) === 'en';
  const params = await searchParams;
  const agentId = strParam(params, 'agent_id', 64);
  const w = strParam(params, 'win', 4);
  const win: AttackWindow = (ATTACK_WINDOWS as readonly string[]).includes(w ?? '') ? (w as AttackWindow) : '30';
  const s = await attackSummary(win, agentId);
  const findingsHref = (q: Record<string, string>) => `/findings${toQuery({ ...q, agent_id: agentId })}`;
  const winLabel: Record<AttackWindow, string> = { '7': t('最近 7 天'), '30': t('最近 30 天'), all: t('全部時間') };
  const hit = Object.keys(s.techniques).length;

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">{t('攻擊手法與法規')}</h1>
          <p className="text-sm text-slate-500">
            {t('把待處理的問題對應到 MITRE ATT&CK（攻擊者常用的手法分類）與常見法規的控制項，看出防線哪裡最弱。點格子可以看是哪些問題。')}
          </p>
        </div>
        <span className="flex gap-1 text-xs">
          {ATTACK_WINDOWS.map((x) => (
            <Link
              key={x}
              href={`/mitre${toQuery({ win: x === '30' ? undefined : x, agent_id: agentId })}`}
              aria-current={x === win ? 'true' : undefined}
              className={`rounded-full border px-2 py-0.5 ${
                x === win ? 'border-teal-600 bg-teal-600 text-white' : 'border-slate-300 text-slate-600 hover:border-teal-500 dark:border-slate-700 dark:text-slate-300'
              }`}
            >
              {winLabel[x]}
            </Link>
          ))}
        </span>
      </header>

      <HostFilter t={t} action="/mitre" current={agentId} keep={{ win: win === '30' ? undefined : win }} />

      <p className="rounded-md bg-slate-50 p-2 text-xs text-slate-600 dark:bg-slate-800/60 dark:text-slate-300">
        {t('{total} 個待處理問題，涉及 {hit} 種手法；{unmapped} 個（效能告警、當機等）沒有對應。對應是參考用，不等於稽核或認證。', {
          total: s.total,
          hit,
          unmapped: s.unmapped,
        })}
      </p>

      <Card title={t('MITRE ATT&CK 手法')}>
        <div className="-mx-2 overflow-x-auto pb-1">
          <div className="flex min-w-max gap-2 px-2">
            {TACTICS.map((tac) => {
              const techs = Object.entries(TECHNIQUES)
                .filter(([, v]) => v.tactics.includes(tac.id))
                .sort(([a], [b]) => a.localeCompare(b));
              if (!techs.length) return null;
              const sum = techs.reduce((n, [id]) => n + (id.includes('.') ? 0 : (s.techniques[id]?.findings ?? 0)), 0);
              return (
                <section key={tac.id} className="w-44 shrink-0">
                  <h3 className="mb-1.5 border-b border-slate-200 pb-1 text-xs font-semibold dark:border-slate-700">
                    {en ? tac.en : tac.zh}
                    {sum ? <span className="ml-1 font-normal text-slate-500">{sum}</span> : null}
                  </h3>
                  <ul className="space-y-1">
                    {techs.map(([id, v]) => {
                      const c = s.techniques[id];
                      const sub = id.includes('.');
                      return (
                        <li key={id} className={sub ? 'pl-3' : ''}>
                          <Tooltip
                            as="div"
                            text={`${id} ${en ? v.en : `${v.zh}（${v.en}）`}：${v.hint}${c ? ` · ${t('{n} 個問題、{h} 台主機', { n: c.findings, h: c.hosts })}` : ''}`}
                          >
                            <Link
                              href={c ? findingsHref({ technique: id }) : techniqueUrl(id)}
                              target={c ? undefined : '_blank'}
                              rel={c ? undefined : 'noreferrer noopener'}
                              className={`block rounded border px-1.5 py-1 text-xs leading-tight hover:ring-1 hover:ring-teal-500 ${heat(c?.findings ?? 0)}`}
                            >
                              <span className="font-mono text-[10px] opacity-70">{id}</span>
                              <span className="block">{en ? v.en : v.zh}</span>
                              {c ? (
                                <span className="text-[11px] font-semibold tabular-nums">
                                  {t('{n} 個問題、{h} 台主機', { n: c.findings, h: c.hosts })}
                                </span>
                              ) : null}
                            </Link>
                          </Tooltip>
                        </li>
                      );
                    })}
                  </ul>
                </section>
              );
            })}
          </div>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          {t('只列我們的檢查能對應到的手法。灰色＝目前沒有相關問題（點了開 MITRE 官方說明）。')} MITRE ATT&CK® © The MITRE Corporation.
        </p>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        {FRAMEWORKS.map((fw) => {
          const ids = Object.keys(CONTROLS).filter((k) => k.startsWith(`${fw.id}:`));
          const open = ids.filter((k) => s.controls[k]);
          return (
            <Card
              key={fw.id}
              title={
                <span className="flex flex-wrap items-baseline gap-x-2">
                  {en ? fw.en : fw.zh}
                  <span className="text-xs font-normal text-slate-500">
                    {t('{n} / {m} 個控制項有待處理問題', { n: open.length, m: ids.length })}
                  </span>
                </span>
              }
            >
              <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
                {ids.map((k) => {
                  const c = s.controls[k];
                  return (
                    <li key={k} className="flex items-center justify-between gap-2 py-1.5">
                      <span className={c ? '' : 'text-slate-400'}>{controlLabel(k, t)}</span>
                      {c ? (
                        <Link href={findingsHref({ control: k })} className="shrink-0 text-xs font-semibold text-amber-700 hover:underline dark:text-amber-300">
                          {t('{n} 個問題、{h} 台主機', { n: c.findings, h: c.hosts })}
                        </Link>
                      ) : (
                        <span className="shrink-0 text-xs text-slate-400">—</span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
