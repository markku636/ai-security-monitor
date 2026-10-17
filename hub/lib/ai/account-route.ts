// /api/ai/accounts/[provider]/* 共用：provider 參數驗證與稽核。
import { audit } from '@/lib/audit';
import { actorOf } from '@/lib/auth/api';
import type { Identity } from '@/lib/auth/access';
import { error, sourceIp } from '@/lib/http';
import { PROVIDERS, type Provider } from './run';

export type ProviderCtx = { params: Promise<{ provider: string }> };

export async function providerOf(ctx: ProviderCtx): Promise<Provider | Response> {
  const { provider } = await ctx.params;
  return (PROVIDERS as string[]).includes(provider) ? (provider as Provider) : error(404, 'unknown_provider');
}

/** 稽核只記 provider、動作、結果；絕不記授權碼或任何 token。 */
export async function auditAccount(req: Request, who: Identity, provider: Provider, action: string, details: Record<string, unknown> = {}): Promise<void> {
  await audit({ actor: actorOf(who), actorRole: 'admin', action: `ai_account.${action}`, targetType: 'ai_provider', targetId: provider, sourceIp: sourceIp(req), details });
}
