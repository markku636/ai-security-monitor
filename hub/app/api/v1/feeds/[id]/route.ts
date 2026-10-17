// 鏡像的原始清單（保留檔頭）；ETag＝sha256，agent 帶 If-None-Match 沒變就 304。
import fs from 'node:fs';
import { identify } from '@/lib/auth/access';
import { error } from '@/lib/http';
import { dataPath, mirrorable, mirrorAllowed, readMeta } from '@/lib/intel/mirror';
import { loadRegistry } from '@/lib/intel/registry';

export const dynamic = 'force-dynamic';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const who = await identify(req);
  if (!mirrorAllowed(who)) return error(401, 'unauthorized');
  const { id } = await ctx.params;
  const feed = loadRegistry().find((f) => f.id === id);
  if (!feed || !mirrorable(feed)) return error(404, 'not_found');
  const meta = readMeta(feed.id);
  const file = dataPath(feed.id);
  if (!meta?.sha256 || !file) return error(404, 'not_mirrored');
  const etag = `"${meta.sha256}"`;
  const headers: Record<string, string> = {
    etag,
    'cache-control': 'private, no-cache',
    'x-asa-feed-license': `${feed.license.name}; ${feed.license.url}`,
    'x-asa-feed-fetched-at': meta.fetched_at ?? '',
    'x-asa-feed-source': meta.url ?? '',
  };
  if (req.headers.get('if-none-match') === etag) return new Response(null, { status: 304, headers });
  return new Response(fs.readFileSync(file), {
    status: 200,
    headers: { ...headers, 'content-type': 'application/octet-stream', 'content-length': String(meta.bytes) },
  });
}
