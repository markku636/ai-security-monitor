// AI 帳號狀態（admin）：每個 CLI 有沒有裝、有沒有登入、登入誰、有沒有被環境變數蓋過、進行中的登入流程。
import { accountStatus, loginView } from '@/lib/ai/accounts';
import { PROVIDERS } from '@/lib/ai/run';
import { apiAdminRead } from '@/lib/auth/api';
import { json } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  const providers = await Promise.all(PROVIDERS.map(async (p) => ({ id: p, status: await accountStatus(p), login: loginView(p) })));
  return json({ providers });
}
