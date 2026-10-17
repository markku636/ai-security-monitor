// 取消進行中的登入（結束 CLI 行程）。
import { auditAccount, providerOf, type ProviderCtx } from '@/lib/ai/account-route';
import { cancelLogin } from '@/lib/ai/accounts';
import { apiWrite } from '@/lib/auth/api';
import { json } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function POST(req: Request, ctx: ProviderCtx): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  const p = await providerOf(ctx);
  if (p instanceof Response) return p;
  const cancelled = cancelLogin(p);
  if (cancelled) await auditAccount(req, who, p, 'login_cancelled');
  return json({ ok: true, cancelled });
}
