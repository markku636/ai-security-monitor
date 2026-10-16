// 管理員：撤銷 API token。
import { audit } from '@/lib/audit';
import { actorOf, apiWrite } from '@/lib/auth/api';
import { revokeApiToken } from '@/lib/auth/tokens';
import { error, json, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  const { id: tokenId } = await ctx.params;
  if (!(await revokeApiToken(tokenId))) return error(404, 'not_found');
  const actor = actorOf(id);
  await audit({ actor, actorRole: 'admin', action: 'token.revoked', targetType: 'api_token', targetId: tokenId, sourceIp: sourceIp(req) });
  return json({ ok: true });
}
