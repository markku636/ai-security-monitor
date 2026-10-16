// 安裝腳本（公開、不含任何金鑰）：預設註冊到這個 Hub，金鑰由使用者在命令列給。
import { error } from '@/lib/http';
import { hubPublicUrl, renderScript } from '@/lib/install';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const text = renderScript('ps1', hubPublicUrl(req.headers, req.url));
  if (!text) return error(404, 'not_found');
  return new Response(text, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
}
