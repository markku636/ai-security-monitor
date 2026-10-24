// 網站掃描端上傳一個步驟的原始輸出（body＝工具輸出 bytes，可 gzip）；scanner／format／exit_code 等放在 query string。
// 原始輸出照存（gzip），解析在 results 時做，解析器改進後可以重跑。
import zlib from 'node:zlib';
import { getDb } from '@/lib/db';
import { BodyTooLarge, error, json, readBytes } from '@/lib/http';
import { zodRule } from '@/lib/ingest/schema';
import { ArtifactMeta } from '@/lib/webscan/contract';
import { runnerAuth } from '@/lib/webscan/http';
import { MAX_ARTIFACT_BYTES, MAX_ARTIFACT_COMPRESSED, storeArtifact } from '@/lib/webscan/jobs';

export const dynamic = 'force-dynamic';

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const db = getDb();
  const who = await runnerAuth(req, db, 'artifacts', 60);
  if (who instanceof Response) return who;
  const { id } = await ctx.params;
  const meta = ArtifactMeta.safeParse(Object.fromEntries(new URL(req.url).searchParams));
  if (!meta.success) return error(400, 'bad_request', { rule: zodRule(meta.error) });
  let raw: Buffer;
  try {
    raw = await readBytes(req, MAX_ARTIFACT_COMPRESSED);
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, e instanceof BodyTooLarge ? 'too_large' : 'bad_request');
  }
  const enc = (req.headers.get('content-encoding') ?? '').toLowerCase();
  if (enc === 'gzip') {
    try {
      raw = zlib.gunzipSync(raw, { maxOutputLength: MAX_ARTIFACT_BYTES });
    } catch (e) {
      return error(e instanceof RangeError ? 413 : 400, e instanceof RangeError ? 'too_large' : 'bad_gzip');
    }
  } else if (enc !== '' && enc !== 'identity') {
    return error(415, 'unsupported_encoding');
  }
  const r = await storeArtifact(db, who, id, meta.data, raw);
  if ('error' in r) return error(r.error === 'not_claimed' ? 409 : r.error === 'too_large' ? 413 : 400, r.error ?? 'bad_request');
  return json(r);
}
