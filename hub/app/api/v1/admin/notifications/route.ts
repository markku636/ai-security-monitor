// 管理員：通知設定總覽（頻道遮罩、規則、最近送出紀錄）與一般設定（訊息語言、Hub 網址）。
import { z } from 'zod';
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { json } from '@/lib/http';
import { hubPublicUrl } from '@/lib/install';
import { notifyView } from '@/lib/notify/admin';
import { notifyAudit, notifyWrite } from '@/lib/notify/route-helpers';
import { getNotifySettings, saveNotifySettings } from '@/lib/notify/service';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  const v = await notifyView(getDb());
  return json({ ...v, suggestedHubUrl: hubPublicUrl(req.headers, req.url) });
}

const Settings = z.object({
  lang: z.enum(['zh-TW', 'en']).optional(),
  hubUrl: z.string().trim().max(500).url().refine((u) => /^https?:\/\//.test(u)).nullable().optional(),
});

export async function PUT(req: Request): Promise<Response> {
  return notifyWrite(req, async (body, actor) => {
    const b = Settings.parse(body);
    const db = getDb();
    const before = await getNotifySettings(db);
    const after = { lang: b.lang ?? before.lang, hubUrl: b.hubUrl === undefined ? before.hubUrl : b.hubUrl?.replace(/\/+$/, '') || null };
    await saveNotifySettings(db, after, actor);
    await notifyAudit(req, actor, 'notification.settings_updated', 'settings', { before, after });
    return json({ settings: after });
  });
}
