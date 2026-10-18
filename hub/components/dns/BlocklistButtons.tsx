'use client';

// 網域分析頁的「加入黑名單／移出黑名單／加入允許清單」：改的是「設定與金鑰 → 防護 DNS」的自訂封鎖與允許清單。
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { Hint } from '@/components/ui/Hint';
import { apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';

const BTN = 'whitespace-nowrap rounded-md border px-2.5 py-1 text-xs disabled:opacity-50';
const DANGER = `${BTN} border-red-600 text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-950`;
const PLAIN = `${BTN} border-slate-300 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800`;

export function BlocklistButtons({ domain, blockedBy, allowedBy }: { domain: string; blockedBy: string | null; allowedBy: string | null }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<string | null>(null);
  const send = (body: Record<string, string[]>, ok: string) => {
    setMsg(null);
    start(async () => {
      const r = await apiPost<{ error?: string }>('/api/v1/admin/dns-protect', body);
      setMsg(r.ok ? ok : t('失敗（HTTP {n}）', { n: r.status }));
      if (r.ok) router.refresh();
    });
  };
  return (
    <div className="flex flex-wrap items-center gap-2">
      {blockedBy ? (
        <>
          <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800 dark:bg-red-950/50 dark:text-red-300">
            {blockedBy === domain ? t('在黑名單上') : t('在黑名單上（{entry}）', { entry: blockedBy })}
          </span>
          {blockedBy === domain ? (
            <button type="button" className={PLAIN} disabled={pending} onClick={() => send({ block_remove: [domain] }, t('已移出黑名單'))}>
              {t('移出黑名單')}
            </button>
          ) : null}
        </>
      ) : (
        <button type="button" className={DANGER} disabled={pending} onClick={() => send({ block_add: [domain] }, t('已加入黑名單'))}>
          {t('加入黑名單')}
        </button>
      )}
      {allowedBy ? (
        <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300">
          {t('在允許清單上')}
        </span>
      ) : !blockedBy ? (
        <button type="button" className={PLAIN} disabled={pending} onClick={() => send({ allow_add: [domain] }, t('已加入允許清單'))}>
          {t('加入允許清單')}
        </button>
      ) : null}
      <Hint text={t('黑名單（含子網域）：防護 DNS 直接擋、每台電腦查到就告警。允許清單：防護 DNS 永遠不擋（情資誤判時用）。在「設定與金鑰 → 防護 DNS」可以整份管理。')} />
      {msg ? <span className="text-xs text-slate-500">{msg}</span> : null}
    </div>
  );
}
