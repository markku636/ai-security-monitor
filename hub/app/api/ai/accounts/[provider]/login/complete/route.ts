// Claude：把使用者在瀏覽器拿到的授權碼交給 `claude auth login`（只寫進 CLI 的 stdin，不保存、不記錄）。
import { z } from 'zod';
import { providerOf, type ProviderCtx } from '@/lib/ai/account-route';
import { completeLogin } from '@/lib/ai/accounts';
import { apiWrite } from '@/lib/auth/api';
import { error, json, readJson } from '@/lib/http';

export const dynamic = 'force-dynamic';
export const maxDuration = 90;

const Body = z.object({ code: z.string().min(1).max(1024) });

export async function POST(req: Request, ctx: ProviderCtx): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  const p = await providerOf(ctx);
  if (p instanceof Response) return p;
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 4 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const r = await completeLogin(p, body.code);
  if (!r.ok) return error(409, r.error);
  return json({ login: r.login });
}
