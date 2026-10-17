// 登出 Hub 主機上的 Claude Code／Codex（刪 CLI 自己存的登入資料）；環境變數設的金鑰不受影響。
import { auditAccount, providerOf, type ProviderCtx } from '@/lib/ai/account-route';
import { accountStatus, logout } from '@/lib/ai/accounts';
import { apiWrite } from '@/lib/auth/api';
import { error, json } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function POST(req: Request, ctx: ProviderCtx): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  const p = await providerOf(ctx);
  if (p instanceof Response) return p;
  const r = await logout(p);
  await auditAccount(req, who, p, 'logout', { ok: r.ok, error: r.error });
  if (!r.ok) return error(r.error === 'not_installed' ? 404 : 500, 'logout_failed', { detail: r.error });
  return json({ ok: true, status: await accountStatus(p) });
}
