// hub 主機上有哪些 AI CLI 可用。
import { apiRead } from '@/lib/auth/api';
import { json } from '@/lib/http';
import { PROVIDERS, resolveBin, running } from '@/lib/ai/run';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  return json({
    providers: PROVIDERS.map((p) => ({ id: p, available: !!resolveBin(p) })),
    running: running(),
  });
}
