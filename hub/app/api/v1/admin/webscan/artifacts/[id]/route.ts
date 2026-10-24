// 管理員：下載掃描器的原始輸出（附件下載，不在瀏覽器裡直接開，避免把目標回傳的內容當 HTML 解讀）。
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error } from '@/lib/http';
import { artifactContent } from '@/lib/webscan/jobs';

export const dynamic = 'force-dynamic';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const who = await apiAdminRead(req);
  if (who instanceof Response) return who;
  const { id } = await ctx.params;
  const n = Number(id);
  if (!Number.isSafeInteger(n) || n <= 0) return error(404, 'not_found');
  const a = await artifactContent(getDb(), n);
  if (!a) return error(404, 'not_found');
  const ext = a.format === 'jsonl' ? 'jsonl' : a.format === 'json' ? 'json' : 'txt';
  return new Response(a.text, {
    headers: {
      'content-type': 'application/octet-stream',
      'content-disposition': `attachment; filename="${a.jobId}-${a.scanner}.${ext}"`,
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-store',
    },
  });
}
