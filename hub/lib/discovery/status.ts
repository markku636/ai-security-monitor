// 「辦公室的電腦找得到這個 Hub 嗎？」：把綁定位址、對外網址、Hub 自己的 mDNS、幫忙廣播的電腦、公司 DNS 的 SRV
// 整理成一句白話結論＋逐項說明。判斷本身是純函式（測試直接呼叫）；gatherDiscovery() 才去讀環境、資料庫、DNS。
import fs from 'node:fs';
import { Resolver } from 'node:dns/promises';
import net from 'node:net';
import { and, isNull, sql } from 'drizzle-orm';
import { agents } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { env, readEnv } from '@/lib/env';
import type { TFn } from '@/lib/i18n/core';
import { mdnsStatus } from './mdns';
import { PLACEHOLDER_DOMAIN, SRV_SERVICE, srvInfo } from './srv';

/** 回報幫忙廣播的電腦，多久沒有心跳就不算數。 */
export const ADVERTISER_FRESH_MS = 15 * 60_000;

export interface Advertiser {
  hostname: string;
  url: string;
  /** 廣播的指紋就是這個 Hub 的。 */
  fingerprintOk: boolean;
  at: Date;
}

export interface DiscoveryInput {
  edition: 'server' | 'standalone';
  /** docker compose 的 AI_SECURITY_MONITOR_HUB_BIND（主機上綁哪個位址）；空白＝不知道。 */
  bind: string;
  publicUrl: string | null;
  inDocker: boolean;
  mdns: { enabled: boolean; running: boolean; error?: string };
  advertisers: Advertiser[];
  /** 公司 DNS 的 SRV：checked＝有查（對外網址是 DNS 名稱才查得了）。 */
  srv: { checked: boolean; found: boolean; name?: string; target?: string; port?: number };
}

export type Level = 'ok' | 'warn' | 'bad' | 'info';

export interface Check {
  id: 'reach' | 'url' | 'mdns' | 'advertiser' | 'srv';
  level: Level;
  title: string;
  text: string;
}

export interface DiscoveryReport {
  /** 區網連得到 Hub（不是只綁 127.0.0.1、對外網址也不是本機）。 */
  reachable: boolean;
  /** 有任何一種自動尋找的方式在運作。 */
  findable: boolean;
  level: Level;
  summary: string;
  checks: Check[];
}

export function isLoopbackHost(h: string): boolean {
  const host = h.replace(/^\[|\]$/g, '').toLowerCase();
  return host === 'localhost' || host === '::1' || host.startsWith('127.') || host.endsWith('.localhost');
}

function urlHost(u: string | null): string | null {
  if (!u) return null;
  try {
    return new URL(u).hostname;
  } catch {
    return null;
  }
}

/** 逐項判斷並給白話結論。 */
export function discoveryReport(i: DiscoveryInput, t: TFn): DiscoveryReport {
  const checks: Check[] = [];
  const bind = i.bind.trim();
  const loopbackBind = bind ? isLoopbackHost(bind) : i.edition === 'standalone';
  const host = urlHost(i.publicUrl);
  const loopbackUrl = host ? isLoopbackHost(host) : false;

  if (loopbackBind) {
    checks.push({
      id: 'reach',
      level: 'bad',
      title: t('區網連不到這個 Hub'),
      text: bind
        ? t('Hub 只綁在 {bind}（只有這台電腦自己連得到）。', { bind })
        : t('單機版預設只綁 127.0.0.1：只有跑 Hub 的這台電腦自己連得到，辦公室其他電腦連不到。'),
    });
  } else {
    checks.push({
      id: 'reach',
      level: bind ? 'ok' : 'info',
      title: bind ? t('區網連得到這個 Hub') : t('應該連得到（伺服器版）'),
      text: bind
        ? t('Hub 綁在 {bind}，同一個網路的電腦都能連進來（防火牆要放行這個 port）。', { bind })
        : t('伺服器版預設綁 0.0.0.0（所有網路介面）；如果還是連不到，請檢查防火牆。'),
    });
  }

  if (!i.publicUrl) {
    checks.push({ id: 'url', level: 'warn', title: t('沒有設定對外網址'), text: t('請設定 AI_SECURITY_MONITOR_HUB_PUBLIC_URL（例：http://192.168.1.10:8088），電腦端與廣播都要用這個網址。') });
  } else if (loopbackUrl) {
    checks.push({
      id: 'url',
      level: 'bad',
      title: t('對外網址是本機位址'),
      text: t('對外網址是 {url}：別台電腦照這個網址會連到自己。請改成這台的區網 IP 或 DNS 名稱（AI_SECURITY_MONITOR_HUB_PUBLIC_URL）。', { url: i.publicUrl }),
    });
  } else {
    checks.push({ id: 'url', level: 'ok', title: t('對外網址'), text: i.publicUrl });
  }

  const mdnsWorks = i.mdns.enabled && i.mdns.running && !i.inDocker;
  if (!i.mdns.enabled) {
    checks.push({ id: 'mdns', level: 'info', title: t('Hub 自己的區網廣播：關閉'), text: t('單機版預設關閉（AI_SECURITY_MONITOR_HUB_MDNS=on 可開啟）。') });
  } else if (!i.mdns.running) {
    checks.push({ id: 'mdns', level: 'warn', title: t('Hub 自己的區網廣播：沒在運作'), text: i.mdns.error ?? t('尚未啟動') });
  } else if (i.inDocker) {
    checks.push({
      id: 'mdns',
      level: 'warn',
      title: t('Hub 自己的區網廣播：在 Docker 裡，可能出不了區網'),
      text: t('Docker Desktop 與預設的 bridge 網路不會把廣播送到區網；Linux 可改用 network_mode: host，或讓一台電腦幫忙廣播（下一項）。'),
    });
  } else {
    checks.push({ id: 'mdns', level: 'ok', title: t('Hub 自己的區網廣播：運作中'), text: t('同一個網段的電腦按「尋找公司的 Hub」就會看到它。') });
  }

  const good = i.advertisers.filter((a) => a.fingerprintOk);
  const wrong = i.advertisers.filter((a) => !a.fingerprintOk);
  if (good.length) {
    checks.push({
      id: 'advertiser',
      level: 'ok',
      title: t('有電腦在幫忙廣播'),
      text: good.map((a) => `${a.hostname} → ${a.url}`).join('；'),
    });
  } else {
    checks.push({
      id: 'advertiser',
      level: mdnsWorks ? 'info' : 'warn',
      title: t('沒有電腦在幫忙廣播'),
      text: t('在跑 Hub 的那台電腦（桌面版「設定 → 讓區網裡的電腦找到這台的 Hub」，或命令列 ai-security-monitor config set hub.advertise_url <區網網址>）打開，背景服務就會一直幫忙廣播。'),
    });
  }
  if (wrong.length) {
    checks.push({
      id: 'advertiser',
      level: 'warn',
      title: t('有電腦廣播的不是這個 Hub'),
      text: t('{hosts} 廣播的指紋和這個 Hub 不同（可能是舊的 Hub）。', { hosts: wrong.map((a) => a.hostname).join('、') }),
    });
  }

  if (!i.srv.checked) {
    checks.push({ id: 'srv', level: 'info', title: t('公司 DNS：沒有檢查'), text: t('對外網址不是公司網域底下的名稱，無法自動檢查 SRV 紀錄（跨網段的電腦要靠它）。') });
  } else if (i.srv.found) {
    checks.push({ id: 'srv', level: 'ok', title: t('公司 DNS：有 SRV 紀錄'), text: `${i.srv.name} → ${i.srv.target}:${i.srv.port}` });
  } else {
    checks.push({ id: 'srv', level: 'info', title: t('公司 DNS：沒有 SRV 紀錄'), text: t('加了之後跨網段的電腦也找得到（下面有現成指令）。') });
  }

  const reachable = !loopbackBind && !loopbackUrl;
  const findable = reachable && (mdnsWorks || good.length > 0 || (i.srv.checked && i.srv.found));
  let summary: string;
  let level: Level;
  if (!reachable) {
    level = 'bad';
    summary = t('辦公室的電腦現在找不到、也連不到這個 Hub：它只開放給這台電腦自己。要給全辦公室用，請照下面「讓區網連得到」改設定。');
  } else if (findable) {
    level = 'ok';
    summary = t('辦公室的電腦可以自動找到這個 Hub：在電腦上按「尋找公司的 Hub」或執行 ai-security-monitor enroll --auto 就會看到它。');
  } else {
    level = 'warn';
    summary = t('辦公室的電腦連得到這個 Hub，但還不會自動找到它：請打開區網廣播或在公司 DNS 加 SRV 紀錄；在那之前，可以把網址直接給同事。');
  }
  return { reachable, findable, level, summary, checks };
}

/** 回報廣播的電腦（最近 15 分鐘有心跳、狀態是廣播中）。 */
export async function advertisers(db: DB, fingerprint: string | null, now = Date.now()): Promise<Advertiser[]> {
  const rows = await db
    .select({ hostname: agents.hostname, advertising: agents.advertising })
    .from(agents)
    .where(and(isNull(agents.deletedAt), sql`${agents.advertising} is not null`))
    .limit(200);
  const norm = (s: string | null | undefined) => (s ?? '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  return rows
    .filter((r) => r.advertising && r.advertising.state === 'advertising' && now - Date.parse(r.advertising.at) <= ADVERTISER_FRESH_MS)
    .map((r) => ({
      hostname: r.hostname,
      url: r.advertising!.url,
      fingerprintOk: !!fingerprint && norm(r.advertising!.fingerprint) === norm(fingerprint),
      at: new Date(r.advertising!.at),
    }));
}

/** 查公司 DNS 的 SRV（1.5 秒內沒回就算沒有）。對外網址不是公司網域的名稱就不查。 */
async function lookupSrv(publicUrl: string | null, fingerprint: string | null): Promise<DiscoveryInput['srv']> {
  const info = publicUrl ? srvInfo(publicUrl, fingerprint ?? '') : null;
  if (!info || info.placeholder || info.domain === PLACEHOLDER_DOMAIN) return { checked: false, found: false };
  const name = `${SRV_SERVICE}.${info.domain}`;
  try {
    const r = new Resolver({ timeout: 1500, tries: 1 });
    const recs = await r.resolveSrv(name);
    const first = recs[0];
    return first ? { checked: true, found: true, name, target: first.name, port: first.port } : { checked: true, found: false, name };
  } catch {
    return { checked: true, found: false, name };
  }
}

function inDocker(): boolean {
  try {
    return fs.existsSync('/.dockerenv');
  } catch {
    return false;
  }
}

/** 綁定位址（docker compose 帶進來的 AI_SECURITY_MONITOR_HUB_BIND；`next start -H` 的 HOSTNAME 也算）。 */
export function bindAddress(): string {
  const b = readEnv('ASA_HUB_BIND');
  if (b) return b;
  const h = (process.env.HOSTNAME ?? '').trim();
  // Docker 映像裡 HOSTNAME=0.0.0.0 是容器內部的綁定，主機上實際綁哪裡要看 compose 的 ports
  return h && net.isIP(h) && !inDocker() ? h : '';
}

export async function gatherDiscovery(db: DB, publicUrl: string | null, fingerprint: string | null): Promise<DiscoveryInput> {
  const [ads, srv] = await Promise.all([advertisers(db, fingerprint).catch(() => []), lookupSrv(publicUrl, fingerprint)]);
  const m = mdnsStatus();
  return {
    edition: env().edition,
    bind: bindAddress(),
    publicUrl,
    inDocker: inDocker(),
    mdns: { enabled: m.enabled, running: m.running, error: m.error },
    advertisers: ads,
    srv,
  };
}
