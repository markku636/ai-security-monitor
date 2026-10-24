'use client';

// 單一目標的動作：被動檢查／主動掃描、三種擁有權驗證、取消工作、刪除目標。
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { Hint } from '@/components/ui/Hint';
import { apiDelete, apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';
import { errorText, profileHint } from './labels';

const BTN = 'whitespace-nowrap rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const SMALL = 'whitespace-nowrap rounded-md border border-slate-300 px-2 py-1 text-sm hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:hover:bg-slate-800';
const CODE = 'block overflow-x-auto whitespace-pre rounded-md bg-slate-100 px-2 py-1 font-mono text-xs dark:bg-slate-800';

type Msg = { ok: boolean; text: string } | null;

function useSend() {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<Msg>(null);
  const send = (path: string, body: unknown, okText: (d: Record<string, unknown>) => string) => {
    setMsg(null);
    start(async () => {
      const r = await apiPost<Record<string, unknown> & { error?: string }>(path, body);
      setMsg(r.ok ? { ok: true, text: okText(r.data) } : { ok: false, text: errorText(t, r.data.error, r.status) });
      if (r.ok) router.refresh();
    });
  };
  return { pending, msg, setMsg, send, start, router };
}

function Message({ msg }: { msg: Msg }) {
  if (!msg) return null;
  return (
    <p className={`text-sm ${msg.ok ? 'text-teal-700 dark:text-teal-400' : 'text-red-700 dark:text-red-400'}`} role="status">
      {msg.text}
    </p>
  );
}

export function ScanButtons({ targetId, canActive, runnersOnline }: { targetId: string; canActive: boolean; runnersOnline: number }) {
  const { t } = useT();
  const { pending, msg, send } = useSend();
  const scan = (profile: 'passive' | 'active_light') => send('/api/v1/admin/webscan/jobs', { target_id: targetId, profile }, () => t('已排入掃描，掃描端領到就會開始。'));
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={SMALL} disabled={pending} onClick={() => scan('passive')}>
          {t('被動檢查')}
        </button>
        <Hint text={profileHint(t, 'passive')} />
        <button type="button" className={BTN} disabled={pending || !canActive} onClick={() => scan('active_light')}>
          {t('主動掃描')}
        </button>
        <Hint text={profileHint(t, 'active_light')} />
      </div>
      {runnersOnline === 0 ? <p className="text-xs text-amber-700 dark:text-amber-400">{t('目前沒有掃描端在線：工作會先排隊，掃描端連上後才會開始（部署方式見「設定與金鑰 → 網站掃描」）。')}</p> : null}
      <Message msg={msg} />
    </div>
  );
}

export function VerifyPanel({ targetId, token, txtName, url, host }: { targetId: string; token: string; txtName: string; url: string; host: string }) {
  const { t } = useT();
  const { pending, msg, send } = useSend();
  const verify = (method: 'dns-txt' | 'well-known' | 'meta') =>
    send(`/api/v1/admin/webscan/targets/${targetId}/verify`, { method }, (d) =>
      method === 'dns-txt' ? (d.verified ? t('驗證成功：DNS TXT 記錄正確。') : t('還沒查到驗證碼：DNS 改完可能要等幾分鐘才生效。')) : t('已排入驗證：掃描端抓到檔案後會更新狀態（重新整理看看）。'),
    );
  const origin = url.replace(/^(https?:\/\/[^/]+).*$/, '$1');
  // 直接用 IP 的網址沒有 DNS 可以放 TXT 記錄
  const isIp = /^[0-9.]+$/.test(host) || host.includes(':');
  return (
    <div className="space-y-3 text-sm">
      <p className="text-slate-600 dark:text-slate-300">{t('主動掃描前要先證明這個網站是你的。選一種方式把下面的驗證碼放上去，再按「檢查」：')}</p>
      {isIp ? null : (
        <div className="space-y-1">
          <div className="font-medium">{t('DNS TXT 記錄（推薦）')}</div>
          <code className={CODE}>{`${txtName}  TXT  "${token}"`}</code>
          <button type="button" className={SMALL} disabled={pending} onClick={() => verify('dns-txt')}>
            {t('檢查 DNS')}
          </button>
        </div>
      )}
      <div className="space-y-1">
        <div className="font-medium">{t('網站上的驗證檔')}</div>
        <code className={CODE}>{`${origin}/.well-known/asm-verify.txt\n${token}`}</code>
        <button type="button" className={SMALL} disabled={pending} onClick={() => verify('well-known')}>
          {t('檢查驗證檔')}
        </button>
      </div>
      <div className="space-y-1">
        <div className="font-medium">{t('網頁裡的 meta 標籤')}</div>
        <code className={CODE}>{`<meta name="asm-verify" content="${token}">`}</code>
        <p className="text-xs text-slate-500">{t('要寫在伺服器送出的 HTML 裡；用 JavaScript 事後加上去的抓不到。')}</p>
        <button type="button" className={SMALL} disabled={pending} onClick={() => verify('meta')}>
          {t('檢查 meta 標籤')}
        </button>
      </div>
      <Message msg={msg} />
    </div>
  );
}

export function CancelJobButton({ jobId }: { jobId: string }) {
  const { t } = useT();
  const { pending, msg, setMsg, start, router } = useSend();
  return (
    <>
      <button
        type="button"
        className="text-xs text-red-700 hover:underline disabled:opacity-50 dark:text-red-400"
        disabled={pending}
        onClick={() =>
          start(async () => {
            const r = await apiDelete(`/api/v1/admin/webscan/jobs/${jobId}`);
            if (r.ok) router.refresh();
            else setMsg({ ok: false, text: t('失敗（HTTP {n}）', { n: r.status }) });
          })
        }
      >
        {t('取消')}
      </button>
      <Message msg={msg} />
    </>
  );
}

export function DeleteTargetButton({ targetId }: { targetId: string }) {
  const { t } = useT();
  const { pending, msg, setMsg, start, router } = useSend();
  const [armed, setArmed] = useState(false);
  return (
    <span className="inline-flex items-center gap-2">
      {armed ? (
        <>
          <span className="text-xs text-slate-500">{t('連同掃描紀錄與發現一起刪掉？')}</span>
          <button
            type="button"
            className="rounded-md bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
            disabled={pending}
            onClick={() =>
              start(async () => {
                const r = await apiDelete(`/api/v1/admin/webscan/targets/${targetId}`);
                if (r.ok) router.push('/web');
                else setMsg({ ok: false, text: t('失敗（HTTP {n}）', { n: r.status }) });
              })
            }
          >
            {t('確定刪除')}
          </button>
          <button type="button" className={SMALL} onClick={() => setArmed(false)}>
            {t('取消')}
          </button>
        </>
      ) : (
        <button type="button" className={SMALL} onClick={() => setArmed(true)}>
          {t('刪除目標')}
        </button>
      )}
      <Message msg={msg} />
    </span>
  );
}
