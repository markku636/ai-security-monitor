// 管理員：立即解除一筆自動封鎖（建立並核准 unblock_ip）。
import { adminWrite } from '@/lib/admin-write';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { release } from '@/lib/response/engine';

export const dynamic = 'force-dynamic';

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  return adminWrite(
    req,
    async (_b, actor) => {
      // release() 自己寫稽核（response.released）
      if (!(await release(getDb(), id, actor))) return error(404, 'not_found');
      return json({ ok: true });
    },
    { body: false },
  );
}
