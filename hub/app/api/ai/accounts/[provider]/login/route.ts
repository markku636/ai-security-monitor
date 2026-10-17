// 開始登入（POST）／查詢進行中的登入（GET）。Claude 回授權網址；Codex 回網址＋一次性代碼。
import { auditAccount, providerOf, type ProviderCtx } from '@/lib/ai/account-route';
import { loginView, startLogin } from '@/lib/ai/accounts';
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { json } from '@/lib/http';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(req: Request, ctx: ProviderCtx): Promise<Response> {
  const who = await apiAdminRead(req);
  if (who instanceof Response) return who;
  const p = await providerOf(ctx);
  if (p instanceof Response) return p;
  return json({ login: loginView(p) });
}

export async function POST(req: Request, ctx: ProviderCtx): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  const p = await providerOf(ctx);
  if (p instanceof Response) return p;
  const actor = actorOf(who);
  const v = await startLogin(p, actor, (done) => {
    // 流程結束（成功／失敗／逾時）時補一筆稽核
    void audit({ actor, actorRole: 'admin', action: `ai_account.login_${done.state}`, targetType: 'ai_provider', targetId: p, details: { error: done.error } });
  });
  await auditAccount(req, who, p, 'login_started', { state: v.state, error: v.error });
  return json({ login: v });
}
