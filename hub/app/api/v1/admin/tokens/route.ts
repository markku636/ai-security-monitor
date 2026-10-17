// 管理員：API token（唯讀，scope read／export／mcp）。明文只在建立時回傳一次。
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { TOKEN_SCOPES, createApiToken, listApiTokens } from '@/lib/auth/tokens';
import { error, json, readJson, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json({ items: await listApiTokens() });
}

const Create = z.object({
  name: z.string().trim().min(1).max(80),
  scopes: z.array(z.enum(TOKEN_SCOPES)).min(1).max(TOKEN_SCOPES.length),
  expires_days: z.number().int().min(1).max(3650).nullish(),
});

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Create>;
  try {
    body = Create.parse(await readJson(req, 4 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const actor = actorOf(id);
  const r = await createApiToken({ name: body.name, scopes: body.scopes, expiresDays: body.expires_days, actor });
  await audit({ actor, actorRole: 'admin', action: 'token.created', targetType: 'api_token', targetId: r.row.id, sourceIp: sourceIp(req), details: { name: body.name, scopes: body.scopes } });
  return json({ token: r.token, item: r.row }, 201);
}
