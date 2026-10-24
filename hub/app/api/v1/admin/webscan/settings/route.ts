// 管理員：網站掃描設定（內網網段白名單、速率、逾時、停用的掃描器、第三方來源開關）。只改有送的欄位。
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { getWebscanSettings, setWebscanSettings } from '@/lib/webscan/settings';
import { remarkIpTargets } from '@/lib/webscan/targets';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json({ settings: await getWebscanSettings(getDb()) });
}

export async function PUT(req: Request): Promise<Response> {
  return adminWrite(req, async (body, actor) => {
    const r = await setWebscanSettings(getDb(), body, actor);
    if ('error' in r) return error(400, r.error);
    const changed = Object.keys(r.after).filter((k) => JSON.stringify(r.after[k as keyof typeof r.after]) !== JSON.stringify(r.before[k as keyof typeof r.before]));
    if (changed.includes('internal_cidrs')) await remarkIpTargets(getDb(), r.after.internal_cidrs);
    await adminAudit(req, actor, 'webscan.settings_updated', 'settings', 'webscan.settings', { changed, internal_cidrs: r.after.internal_cidrs });
    return json({ ok: true, settings: r.after });
  });
}
