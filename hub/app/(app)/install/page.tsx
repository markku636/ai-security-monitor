import { headers } from 'next/headers';
import { AutoApproveForm, CopyBlock, EnrollRequestsPanel } from '@/components/admin/EnrollRequests';
import { InstallKeyMaker } from '@/components/admin/KeyManagers';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Hint } from '@/components/ui/Hint';
import { requireAdmin } from '@/lib/auth/require';
import { getDb } from '@/lib/db';
import { mdnsStatus } from '@/lib/discovery/mdns';
import { discoveryReport, gatherDiscovery, type Level } from '@/lib/discovery/status';
import { srvCommands, srvInfo } from '@/lib/discovery/srv';
import { hubIdentity, keylessEnabled } from '@/lib/enroll/identity';
import { getAutoApproveCidrs, listRequests } from '@/lib/enroll/store';
import { env } from '@/lib/env';
import { peerIpHookInstalled } from '@/lib/http';
import { getT } from '@/lib/i18n/server';
import { hubPublicUrl, scriptsDir } from '@/lib/install';

export const dynamic = 'force-dynamic';

export default async function InstallPage() {
  await requireAdmin();
  const { t } = await getT();
  const hub = hubPublicUrl(await headers());
  const db = getDb();
  const [identity, requests, cidrs] = await Promise.all([
    hubIdentity(db).catch(() => null),
    listRequests(db, { status: 'pending' }).catch(() => ({ items: [], counts: null })),
    getAutoApproveCidrs(db).catch(() => [] as string[]),
  ]);
  const fp = identity?.fingerprint ?? null;
  const keyless = keylessEnabled();
  const discovery = discoveryReport(await gatherDiscovery(db, hub, fp), t);
  const tip = {
    fingerprint: t('指紋是這個 Hub 專屬的一串代碼（由 Hub 的金鑰算出來）。電腦端第一次連上時會記住它，之後如果有人假冒 Hub，指紋就會對不上。'),
    cidr: t('CIDR 是寫一段 IP 範圍的方法：192.168.1.0/24 代表 192.168.1.0～192.168.1.255；只寫一個 IP 就只算那一台。'),
    subnet: t('網段＝一段連續的 IP 位址，通常就是同一個辦公室或機房的網路。'),
    mdns: t('mDNS 是區網內的「廣播找人」：同一個網路裡的電腦不用輸入網址，就能自動找到 Hub（跟印表機被自動找到的原理一樣）。'),
    srv: t('SRV 是公司 DNS 裡的一種紀錄，告訴電腦「某個服務在哪台主機、哪個 port」。加了之後，跨網段的電腦也能自動找到 Hub。'),
    txt: t('TXT 紀錄是附在 DNS 名稱上的文字，這裡放 Hub 的網址與指紋，讓電腦端確認找到的是對的 Hub。'),
  };
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('新增主機')}</h1>
        <p className="text-sm text-slate-500">{t('在要保護的電腦或伺服器上執行一行指令：下載 ai-security-monitor、比對 SHA256、註冊到這個 Hub，並設定開機自動啟動。')}</p>
      </header>

      <Card
        title={
          <>
            {t('Hub 指紋')}
            <Hint text={tip.fingerprint} />
          </>
        }
      >
        {fp ? (
          <div className="space-y-1">
            <div className="font-mono text-2xl font-semibold tracking-widest text-teal-700 dark:text-teal-400">{fp}</div>
            <p className="text-sm text-slate-600 dark:text-slate-300">{t('電腦端顯示的指紋要跟這裡一樣，才是公司的 Hub')}</p>
          </div>
        ) : (
          <p className="text-sm text-red-700 dark:text-red-400">{t('讀不到 Hub 身分（資料庫連不上？）。')}</p>
        )}
      </Card>

      <DiscoveryStatusCard report={discovery} hub={hub} />

      <Card title={t('待核准的主機')}>
        {!keyless ? (
          <p className="mb-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
            {t('免金鑰加入已被關閉（ASA_HUB_ENROLL_REQUESTS=off），電腦端無法送出申請。')}
          </p>
        ) : null}
        <EnrollRequestsPanel initial={requests.items} />
      </Card>

      {!hub ? (
        <EmptyState title={t('無法判斷這個 Hub 的對外網址')}>{t('請設定 ASA_HUB_PUBLIC_URL（例：https://hub.example.com）。')}</EmptyState>
      ) : (
        <>
          <Card title={t('免金鑰安裝指令')}>
            <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">
              {t('下載預填此 Hub 的安裝指令（不含金鑰）')}
              {t('：裝好後電腦端會送出加入申請，並顯示申請碼與 Hub 指紋；你在上面「待核准的主機」對照後按核准即可。')}
            </p>
            <div className="space-y-2">
              <CopyBlock label={t('Windows 伺服器（系統管理員 PowerShell）')} value={`$env:AI_SECURITY_MONITOR_SERVICE='system'; irm ${hub}/install.ps1 | iex`} />
              <CopyBlock label={t('Windows 個人電腦（PowerShell）')} value={`$env:AI_SECURITY_MONITOR_SERVICE='user'; irm ${hub}/install.ps1 | iex`} />
              <CopyBlock label={t('Linux／macOS 伺服器（開機就啟動，需要 sudo）')} value={`curl -fsSL ${hub}/install.sh | sh -s -- --service system`} />
              <CopyBlock label={t('Linux／macOS 個人電腦（登入時啟動）')} value={`curl -fsSL ${hub}/install.sh | sh -s -- --service user`} />
              <CopyBlock label={t('已經裝好 ai-security-monitor')} value="ai-security-monitor enroll --auto" />
            </div>
            <p className="mt-3 flex flex-wrap gap-4 text-sm">
              <a className="text-teal-700 hover:underline dark:text-teal-400" href="/install.ps1" download="install.ps1">
                {t('下載 install.ps1（Windows）')}
              </a>
              <a className="text-teal-700 hover:underline dark:text-teal-400" href="/install.sh" download="install.sh">
                {t('下載 install.sh（Linux／macOS）')}
              </a>
            </p>
          </Card>

          <Card
            title={
              <>
                {t('自動核准的網段')}
                <Hint text={tip.subnet} />
              </>
            }
          >
            <p className="mb-2 text-sm text-slate-600 dark:text-slate-300">
              {t('從這些網段送來的申請會直接核准，不用人按。一行一個')}
              {' '}
              <abbr className="cursor-help underline decoration-dotted underline-offset-2" title={tip.cidr}>
                CIDR
              </abbr>
              {t('（例：192.168.10.0/24）。留空＝全部都要人工核准。只建議填公司內部、你信得過的網路。')}
            </p>
            <AutoApproveForm initial={cidrs} peerIpAvailable={peerIpHookInstalled() || env().trustProxy} />
          </Card>

          <DiscoveryCard hub={hub} fp={fp} tip={tip} />

          <Card title={t('用註冊金鑰安裝（另一種方式）')}>
            <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">{t('不想逐台核准，或電腦連不到這個 Hub 的核准流程時：先建立一把註冊金鑰，指令裡帶著金鑰就會直接加入。')}</p>
            <InstallKeyMaker hub={hub} />
          </Card>
          <Card title={t('說明')}>
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-600 dark:text-slate-300">
              <li>{t('安裝腳本從 GitHub Releases 下載 ai-security-monitor，與 Release 的 SHA256SUMS 比對不符就停止。')}</li>
              <li>{t('「伺服器」裝成系統服務（開機就啟動，需要系統管理員／sudo）；「個人電腦」在使用者登入時啟動，不需要系統管理員。')}</li>
              <li>{t('腳本本身是公開的、不含金鑰：{hub}/install.sh、{hub}/install.ps1。金鑰只出現在你複製的指令裡。', { hub })}</li>
              <li>{t('免金鑰加入：申請送到 Hub 後要管理員核准才拿得到金鑰，而且那把金鑰只能給那一台主機用。')}</li>
              <li>{t('裝好後的管理：ai-security-monitor service status、ai-security-monitor service logs、ai-security-monitor self-update --yes。')}</li>
            </ul>
            {!scriptsDir() ? <p className="mt-2 text-sm text-amber-700 dark:text-amber-400">{t('找不到安裝腳本（scripts/install.*），/install.sh 會回 404。')}</p> : null}
          </Card>
        </>
      )}
    </div>
  );
}

const LEVEL_CLASS: Record<Level, string> = {
  ok: 'border-green-300 bg-green-50 text-green-900 dark:border-green-800 dark:bg-green-950/40 dark:text-green-200',
  warn: 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200',
  bad: 'border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200',
  info: 'border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-950/40 dark:text-slate-300',
};
const LEVEL_MARK: Record<Level, string> = { ok: '✓', warn: '!', bad: '✗', info: '·' };

/** 「辦公室的電腦找得到這個 Hub 嗎？」：一句結論＋逐項說明＋怎麼改。 */
async function DiscoveryStatusCard({ report, hub }: { report: ReturnType<typeof discoveryReport>; hub: string | null }) {
  const { t } = await getT();
  return (
    <Card title={t('辦公室的電腦找得到這個 Hub 嗎？')}>
      <p className={`mb-3 rounded-md border p-2 text-sm ${LEVEL_CLASS[report.level]}`}>{report.summary}</p>
      <ul className="space-y-1.5 text-sm">
        {report.checks.map((c, i) => (
          <li key={`${c.id}-${i}`} className="flex gap-2">
            <span
              className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-xs font-semibold ${LEVEL_CLASS[c.level]}`}
              aria-hidden
            >
              {LEVEL_MARK[c.level]}
            </span>
            <span>
              <span className="font-medium">{c.title}</span>
              <span className="text-slate-600 dark:text-slate-300">：{c.text}</span>
            </span>
          </li>
        ))}
      </ul>
      {!report.reachable ? (
        <details className="mt-3 text-sm" open>
          <summary className="cursor-pointer font-medium">{t('讓區網連得到（給全辦公室用）')}</summary>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-slate-600 dark:text-slate-300">
            <li>
              {t('建議改用伺服器版：')} <code className="font-mono text-xs">docker compose -f docker/compose.yml --env-file .env up -d</code>
              {t('（預設綁 0.0.0.0、開啟區網廣播）。')}
            </li>
            <li>
              {t('或在單機版的 .env 加上')} <code className="font-mono text-xs">AI_SECURITY_MONITOR_HUB_BIND=0.0.0.0</code> {t('與')}{' '}
              <code className="font-mono text-xs">AI_SECURITY_MONITOR_HUB_PUBLIC_URL=http://&lt;{t('這台的區網 IP')}&gt;:8088</code>
              {t('，再重新執行 docker compose up -d。')}
            </li>
            <li>{t('Windows／macOS 的防火牆要允許這個 port（預設 8088）連入。')}</li>
          </ol>
          <p className="mt-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
            {t('安全提醒：打開之後，同一個網路的任何人都看得到 Hub 的登入頁、也能呼叫上傳 API。一定要設管理員金鑰（單機版本來就必填）、只在公司內網使用；要從外面連，請放在 https 反向代理後面，不要直接開到網際網路。')}
          </p>
        </details>
      ) : null}
      {report.reachable && !report.findable && hub ? (
        <p className="mt-3 text-xs text-slate-500">
          {t('同事也可以直接用這個網址加入：')} <code className="font-mono">ai-security-monitor enroll --hub {hub}</code>
        </p>
      ) : null}
    </Card>
  );
}

type Tips = Record<'mdns' | 'srv' | 'txt', string>;

/** 自動尋找狀態：mDNS 廣播、Docker 注意事項、公司 DNS 要加的 SRV／TXT。 */
async function DiscoveryCard({ hub, fp, tip }: { hub: string; fp: string | null; tip: Tips }) {
  const { t } = await getT();
  const mdns = mdnsStatus();
  const srv = fp ? srvInfo(hub, fp) : null;
  const cmds = srv ? srvCommands(srv) : null;
  let mdnsText;
  if (!mdns.enabled) mdnsText = <span className="text-slate-500">{t('關閉（ASA_HUB_MDNS=on 可開啟；伺服器版預設開）')}</span>;
  else if (mdns.running) mdnsText = <span className="text-green-700 dark:text-green-400">{t('廣播中（port {p}）', { p: mdns.port ?? '—' })}</span>;
  else mdnsText = <span className="text-amber-700 dark:text-amber-400">{t('已開啟但沒在廣播：{e}', { e: mdns.error ?? t('尚未啟動') })}</span>;
  return (
    <Card title={t('自動尋找狀態')}>
      <div className="space-y-3 text-sm">
        <div>
          <span className="font-medium">
            {t('區網廣播')} (
            <abbr className="cursor-help underline decoration-dotted underline-offset-2" title={tip.mdns}>
              mDNS
            </abbr>
            )：
          </span>{' '}
          {mdnsText}
        </div>
        <p className="rounded-md border border-slate-200 bg-slate-50 p-2 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-950/40 dark:text-slate-300">
          {t('Hub 跑在 Docker 裡時要注意：Docker Desktop 與預設的 bridge 網路不會把廣播送到區網。Linux 請改用 network_mode: host，或在區網裡的一台電腦執行：')}{' '}
          <code className="font-mono">ai-security-monitor hub advertise --url {hub}</code>
        </p>
        <div>
          <div className="mb-1 font-medium">
            {t('公司 DNS 紀錄（跨網段也找得到）')}
            <Hint text={tip.srv} />
          </div>
          {srv && cmds ? (
            <div className="space-y-2">
              <p className="text-xs text-slate-500">
                {t('在公司 DNS 加 SRV 與 TXT 紀錄')}
                <Hint text={tip.txt} />
                {srv.placeholder ? ` ${t('（{d} 是範例網域，請換成公司實際的網域；目標主機要是 Hub 的 DNS 名稱）', { d: srv.domain })}` : ''}
              </p>
              <CopyBlock label={t('Windows DNS Server（PowerShell）')} value={cmds.windows} />
              <CopyBlock label={t('BIND zone 檔')} value={cmds.bind} />
              <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
                <dt className="text-slate-500">SRV</dt>
                <dd className="font-mono">
                  {srv.name} → {srv.target}:{srv.port}
                </dd>
                <dt className="text-slate-500">TXT</dt>
                <dd className="break-all font-mono">{srv.txt.map((x) => `"${x}"`).join(' ')}</dd>
              </dl>
            </div>
          ) : (
            <p className="text-xs text-slate-500">{t('設定 ASA_HUB_PUBLIC_URL 後這裡會顯示要加的紀錄。')}</p>
          )}
        </div>
      </div>
    </Card>
  );
}
