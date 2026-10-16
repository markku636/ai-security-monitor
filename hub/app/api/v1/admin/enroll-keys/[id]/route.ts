// 管理員：撤銷註冊金鑰（用這把金鑰的 agent 之後都無法上傳）。
import { audit } from '@/lib/audit';
import { actorOf, apiWrite } from '@/lib/auth/api';
import { revokeEnrollKey } from '@/lib/auth/tokens';
import { error, json, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  const { id: keyId } = await ctx.params;
  if (!(await revokeEnrollKey(keyId))) return error(404, 'not_found');
  const actor = actorOf(id);
  await audit({ actor, actorRole: 'admin', action: 'enroll_key.revoked', targetType: 'enroll_key', targetId: keyId, sourceIp: sourceIp(req) });
  return json({ ok: true });
}
