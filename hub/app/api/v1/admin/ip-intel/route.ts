// 管理員：IP 外部情資來源的金鑰與開關。金鑰只寫不讀（回傳只給遮罩過的提示）。
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { error, json, readJson, sourceIp } from '@/lib/http';
import { configStatus, getConfig, saveConfig } from '@/lib/ipintel/service';
import { PROVIDER_IDS, type ProviderId } from '@/lib/ipintel/types';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json(await configStatus());
}

const Id = z.enum(PROVIDER_IDS);
const Body = z.object({
  /** 字串＝設定新金鑰；null＝清除；沒給＝不變。 */
  keys: z.partialRecord(Id, z.string().trim().max(256).nullable()).default({}),
  disabled: z.array(Id).max(PROVIDER_IDS.length).optional(),
});

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 8 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const cfg = await getConfig();
  const changed: string[] = [];
  for (const [k, v] of Object.entries(body.keys) as [ProviderId, string | null | undefined][]) {
    if (v === undefined) continue;
    if (v) cfg.keys[k] = v;
    else delete cfg.keys[k];
    changed.push(k);
  }
  if (body.disabled) cfg.disabled = [...new Set(body.disabled)];
  const actor = actorOf(id);
  await saveConfig(cfg, actor);
  // 稽核只記哪些來源的金鑰被改，不記金鑰本身
  await audit({
    actor,
    actorRole: 'admin',
    action: 'ip_intel.config',
    targetType: 'settings',
    targetId: 'ipintel.config',
    sourceIp: sourceIp(req),
    details: { keys_changed: changed, disabled: cfg.disabled },
  });
  return json(await configStatus());
}
