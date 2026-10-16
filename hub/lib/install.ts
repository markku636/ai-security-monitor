// /install 頁與 /install.sh、/install.ps1：讀 repo 的 scripts/install.*，把這個 Hub 的網址填進預設值。
import fs from 'node:fs';
import path from 'node:path';
import { env } from '@/lib/env';

export function scriptsDir(): string | null {
  const candidates = [process.env.ASA_HUB_SCRIPTS_DIR, path.resolve(process.cwd(), '../scripts'), path.resolve(process.cwd(), 'scripts')];
  for (const c of candidates) {
    if (c && fs.existsSync(path.join(c, 'install.sh'))) return c;
  }
  return null;
}

/** 只接受單純的 http(s) 網址（會被放進 shell／PowerShell 字串）。 */
export function safeHubUrl(u: string | null | undefined): string | null {
  if (!u) return null;
  const s = u.trim().replace(/\/+$/, '');
  return /^https?:\/\/[A-Za-z0-9.\-]+(:\d{1,5})?(\/[A-Za-z0-9._~\-/]*)?$/.test(s) ? s : null;
}

/** 對外網址：ASA_HUB_PUBLIC_URL，否則用請求的 Host（反向代理後面要開 ASA_HUB_TRUST_PROXY）。 */
export function hubPublicUrl(h: { get(name: string): string | null }, reqUrl?: string): string | null {
  const configured = safeHubUrl(process.env.ASA_HUB_PUBLIC_URL);
  if (configured) return configured;
  const proto = env().trustProxy ? h.get('x-forwarded-proto')?.split(',')[0]?.trim() : null;
  const host = (env().trustProxy ? h.get('x-forwarded-host') : null) ?? h.get('host');
  if (host) return safeHubUrl(`${proto || (reqUrl ? new URL(reqUrl).protocol.replace(':', '') : 'http')}://${host}`);
  return reqUrl ? safeHubUrl(new URL(reqUrl).origin) : null;
}

export function renderScript(kind: 'sh' | 'ps1', hub: string | null): string | null {
  const dir = scriptsDir();
  if (!dir) return null;
  let text = fs.readFileSync(path.join(dir, kind === 'sh' ? 'install.sh' : 'install.ps1'), 'utf8');
  const url = safeHubUrl(hub);
  if (url) {
    text = kind === 'sh' ? text.replace(/^DEFAULT_HUB=""$/m, `DEFAULT_HUB="${url}"`) : text.replace(/^\$DefaultHub = ''$/m, `$DefaultHub = '${url}'`);
  }
  return text;
}
