import Link from 'next/link';
import { notFound } from 'next/navigation';
import { isIP } from 'node:net';
import { GeoAttribution } from '@/components/security/ConnectionsTable';
import { IndicatorDetails } from '@/components/security/IndicatorDetails';
import { IpNoteEditor } from '@/components/security/IpNoteEditor';
import { IpRiskBadge, IpRiskIcon } from '@/components/security/IpRisk';
import { IpThreatIntel } from '@/components/security/IpThreatIntel';
import { Card } from '@/components/ui/Card';
import { requireAdmin } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';
import { cachedRiskMap, getIpIntelView } from '@/lib/ipintel/service';
import { getIpNote } from '@/lib/queries/ipnotes';

export const dynamic = 'force-dynamic';

const BTN = 'rounded-md border border-teal-600 px-2.5 py-1 text-xs text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950';

/** 外部查詢只放連結（使用者自己點），hub 不會把 IP 送出去。 */
function externalLookups(ip: string): [string, string][] {
  const e = encodeURIComponent(ip);
  return [
    ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${e}`],
    ['AbuseIPDB', `https://www.abuseipdb.com/check/${e}`],
    ['GreyNoise', `https://viz.greynoise.io/ip/${e}`],
    ['Shodan', `https://www.shodan.io/host/${e}`],
    ['IPinfo', `https://ipinfo.io/${e}`],
  ];
}

export default async function IpPage({ params }: { params: Promise<{ ip: string }> }) {
  await requireAdmin();
  const { t } = await getT();
  const ip = decodeURIComponent((await params).ip).trim();
  if (!isIP(ip)) notFound();
  const [note, riskMap] = await Promise.all([getIpNote(ip), cachedRiskMap([ip])]);
  const risk = riskMap.get(ip);
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <p className="text-xs text-slate-500">
            <Link href="/connections" className="hover:underline">
              {t('連線')}
            </Link>{' '}
            / {t('IP 分析')}
          </p>
          <h1 className="flex flex-wrap items-center gap-2 font-mono text-xl font-semibold">
            <IpRiskIcon t={t} risk={risk} />
            {ip}
            {risk?.kind === 'scored' ? (
              <span className="font-sans text-sm font-normal">
                <IpRiskBadge t={t} risk={risk} />
              </span>
            ) : null}
          </h1>
          <p className="text-sm text-slate-500">
            {t('這個 IP 在所有主機裡的紀錄：哪些情資來源列名、哪台主機的哪個程式連過它、為什麼被判可疑。')}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link href={`/ai?scope=indicator&q=${encodeURIComponent(ip)}`} className={BTN}>
            {t('請 AI 分析這個 IP')}
          </Link>
          <Link href={`/connections?q=${encodeURIComponent(ip)}`} className={BTN}>
            {t('在連線頁篩選')}
          </Link>
        </div>
      </header>
      <Card title={t('人工備註')}>
        <IpNoteEditor
          ip={ip}
          initial={note?.note ?? ''}
          updatedAt={note?.updatedAt?.toISOString() ?? null}
          updatedBy={note?.updatedBy ?? null}
        />
      </Card>
      <Card title={t('外部威脅情資')}>
        <IpThreatIntel view={await getIpIntelView(ip)} />
      </Card>
      <IndicatorDetails t={t} q={ip} title={t('情資與連線紀錄')} />
      <Card title={t('外部查詢')}>
        <p className="mb-2 text-xs text-slate-500">{t('在新分頁開啟第三方網站查這個 IP；hub 不會自動把 IP 送給它們。')}</p>
        <div className="flex flex-wrap gap-2">
          {externalLookups(ip).map(([name, href]) => (
            <a key={name} href={href} target="_blank" rel="noreferrer noopener" className={BTN}>
              {name}
            </a>
          ))}
        </div>
      </Card>
      <GeoAttribution t={t} />
    </div>
  );
}
