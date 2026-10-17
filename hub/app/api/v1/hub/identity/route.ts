// Hub 身分（公開、不需金鑰）：電腦端自動尋找到 Hub 後先來這裡拿公鑰與指紋，
// 帶 nonce 時用 Hub 私鑰簽回去，證明對方真的持有這把金鑰（不是只複製了公鑰的假 Hub）。
import { hit } from '@/lib/auth/ratelimit';
import { getDb } from '@/lib/db';
import { hubIdentity, hubName, identityMessage, keylessEnabled, sign } from '@/lib/enroll/identity';
import { getJoinMode } from '@/lib/enroll/store';
import { env } from '@/lib/env';
import { error, json, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;

export async function GET(req: Request): Promise<Response> {
  if (hit(`hub_identity:${sourceIp(req)}`, 60_000) > 120) {
    return json({ error: 'too_many_requests' }, 429, { 'retry-after': '60' });
  }
  const nonce = new URL(req.url).searchParams.get('nonce');
  if (nonce !== null && !NONCE_RE.test(nonce)) return error(400, 'bad_nonce');
  const db = getDb();
  const id = await hubIdentity(db);
  // mode 讓電腦端事先知道要不要顯示「等候管理員核准」（auto＝送出就加入）
  const { mode } = await getJoinMode(db);
  const e = env();
  return json({
    name: hubName(),
    version: e.version,
    edition: e.edition,
    algorithm: 'ed25519',
    public_key: id.publicKeyB64,
    fingerprint: id.fingerprint,
    enrollment: { keyless: keylessEnabled(), mode },
    ...(nonce !== null ? { nonce, signature: sign(id, identityMessage(nonce, id.fingerprint)) } : {}),
  });
}
