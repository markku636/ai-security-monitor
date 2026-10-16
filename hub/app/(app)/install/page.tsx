import { headers } from 'next/headers';
import { InstallKeyMaker } from '@/components/admin/KeyManagers';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { requireAdmin } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';
import { hubPublicUrl, scriptsDir } from '@/lib/install';

export const dynamic = 'force-dynamic';

export default async function InstallPage() {
  await requireAdmin();
  const { t } = await getT();
  const hub = hubPublicUrl(await headers());
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('安裝代理程式')}</h1>
        <p className="text-sm text-slate-500">{t('在要保護的電腦或伺服器上執行一行指令：下載 asa、比對 SHA256、註冊到這個 Hub，並設定開機自動啟動。')}</p>
      </header>
      {!hub ? (
        <EmptyState title={t('無法判斷這個 Hub 的對外網址')}>{t('請設定 ASA_HUB_PUBLIC_URL（例：https://hub.example.com）。')}</EmptyState>
      ) : (
        <>
          <Card title={t('1. 建立註冊金鑰')}>
            <InstallKeyMaker hub={hub} />
          </Card>
          <Card title={t('2. 說明')}>
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-600 dark:text-slate-300">
              <li>{t('安裝腳本從 GitHub Releases 下載 asa，與 Release 的 SHA256SUMS 比對不符就停止。')}</li>
              <li>{t('「伺服器」裝成系統服務（開機就啟動，需要系統管理員／sudo）；「個人電腦」在使用者登入時啟動，不需要系統管理員。')}</li>
              <li>{t('腳本本身是公開的、不含金鑰：{hub}/install.sh、{hub}/install.ps1。金鑰只出現在你複製的指令裡。', { hub })}</li>
              <li>{t('裝好後的管理：asa service status、asa service logs、asa self-update --yes。')}</li>
            </ul>
            {!scriptsDir() ? <p className="mt-2 text-sm text-amber-700 dark:text-amber-400">{t('找不到安裝腳本（scripts/install.*），/install.sh 會回 404。')}</p> : null}
          </Card>
        </>
      )}
    </div>
  );
}
