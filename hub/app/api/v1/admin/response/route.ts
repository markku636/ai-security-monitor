// 管理員：自動回應總覽（設定、規則、封鎖紀錄、群組、主機）與全域設定（開關、白名單網段）。
import { z } from 'zod';
import { adminAudit, adminWrite, InputError } from '@/lib/admin-write';
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { normalizeCidrList } from '@/lib/enroll/cidr';
import { json } from '@/lib/http';
import { responseView } from '@/lib/response/admin';
import { getResponseSettings, saveResponseSettings } from '@/lib/response/engine';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json(await responseView(getDb()));
}

const Body = z.object({ enabled: z.boolean().optional(), allowlist: z.array(z.string().max(64)).max(64).optional() });

export async function PUT(req: Request): Promise<Response> {
  return adminWrite(req, async (body, actor) => {
    const b = Body.parse(body);
    const db = getDb();
    const before = await getResponseSettings(db);
    let allowlist = before.allowlist;
    if (b.allowlist !== undefined) {
      const list = normalizeCidrList(b.allowlist);
      if (!Array.isArray(list)) throw new InputError(list.error);
      allowlist = list;
    }
    const after = { enabled: b.enabled ?? before.enabled, allowlist };
    await saveResponseSettings(db, after, actor);
    await adminAudit(req, actor, 'response.settings_updated', 'settings', 'response', { before, after });
    return json({ settings: after });
  });
}
