// DNS 頁的「怎麼用」：四個步驟（看紀錄與告警 → 加黑名單 → 架防護 DNS 擋下來 → 每台電腦的設定）。
import Link from 'next/link';
import { Term } from '@/components/ui/Hint';
import type { TFn } from '@/lib/i18n/core';

const CODE = 'rounded bg-slate-100 px-1 font-mono text-xs dark:bg-slate-800';

export function DnsHowTo({ t, open }: { t: TFn; open: boolean }) {
  return (
    <details className="rounded-xl border border-slate-200 bg-white p-4 text-sm shadow-sm dark:border-slate-800 dark:bg-slate-900" open={open}>
      <summary className="cursor-pointer font-semibold text-slate-700 dark:text-slate-200">{t('DNS 防禦怎麼用')}</summary>
      <ol className="mt-3 list-decimal space-y-3 pl-5 text-slate-600 dark:text-slate-300">
        <li>
          <b>{t('看紀錄與告警')}</b>：{t('裝了 ai-security-monitor 的電腦會自動記錄 DNS 查詢、每分鐘上傳。可疑的（情資列名、')}
          <Term hint={t('把資料編碼進大量又長又亂的子網域送出去。')}>{t('DNS 通道')}</Term>
          {t('、亂數產生的網域、大量查無此網域）會變成上面的 DNS 告警。點網域可以看誰查過、解析到哪裡。')}
        </li>
        <li>
          <b>{t('加黑白名單')}</b>：{t('在上面「黑白名單」或網域分析頁按「加入黑名單／加入白名單」（全公司、含子網域）。黑名單：任何一台電腦查到都會告警，用防護 DNS 的電腦直接被擋；白名單：不擋、不告警。單台電腦也能自己加：')}
          <span className={CODE}>ai-security-monitor dns block bad.example</span>／<span className={CODE}>dns allow ok.example</span>
        </li>
        <li>
          <b>{t('真的擋下來')}</b>：{t('在一台常開的電腦跑')} <span className={CODE}>ai-security-monitor dns-server</span>{t('（或改用 Hub 含防護 DNS 的 compose：compose.dns.yml），到')}{' '}
          <Link href="/admin?tab=dns" className="text-teal-700 hover:underline dark:text-teal-400">
            {t('設定與金鑰 → 防護 DNS')}
          </Link>{' '}
          {t('打開封鎖，再把路由器 DHCP 的 DNS 改成它，或在個別電腦執行')} <span className={CODE}>ai-security-monitor dns use-hub --yes</span>
          {t('（連不上會自動改回）。')}
        </li>
        <li>
          <b>{t('每台電腦的設定')}</b>：{t('桌面版「設定 → DNS」，或命令列')} <span className={CODE}>config set dns.upload alerts</span>
          {t('（只傳告警）、')}
          <span className={CODE}>config set dns.upload off</span>
          {t('（不上傳）、')}
          <span className={CODE}>config set dns.enabled false</span>
          {t('（關掉監看）。')}
        </li>
      </ol>
      <p className="mt-3 text-xs text-slate-500">
        {t('完整說明：')}
        <a className="text-teal-700 hover:underline dark:text-teal-400" href="https://github.com/markku636/ai-security-monitor/blob/main/docs/dns.md" target="_blank" rel="noreferrer">
          docs/dns.md
        </a>
        {' · '}
        <a className="text-teal-700 hover:underline dark:text-teal-400" href="https://github.com/markku636/ai-security-monitor/blob/main/docs/dns-server.md" target="_blank" rel="noreferrer">
          docs/dns-server.md
        </a>
      </p>
    </details>
  );
}
