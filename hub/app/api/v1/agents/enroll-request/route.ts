// 免金鑰加入：電腦端不帶任何金鑰送出申請，管理員在「新增主機」頁核准（或來源在自動核准網段內）後才拿得到金鑰。
import { audit } from '@/lib/audit';
import { hit } from '@/lib/auth/ratelimit';
import { getDb } from '@/lib/db';
import { hubIdentity, hubInfo, keylessEnabled } from '@/lib/enroll/identity';
import { createRequest, CREATE_WINDOW_MS, CREATES_PER_WINDOW, EnrollRequest, POLL_INTERVAL_S } from '@/lib/enroll/store';
import { error, json, peerIp, sourceIp } from '@/lib/http';
import { IngestRejected, readIngestBody } from '@/lib/ingest/guard';
import { zodRule } from '@/lib/ingest/schema';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  if (!keylessEnabled()) return error(403, 'enroll_requests_disabled');
  const ip = sourceIp(req);
  if (hit(`enroll_create:${ip}`, CREATE_WINDOW_MS) > CREATES_PER_WINDOW) {
    return json({ error: 'too_many_requests', retry_after_ms: CREATE_WINDOW_MS }, 429, { 'retry-after': String(CREATE_WINDOW_MS / 1000) });
  }
  let raw: unknown;
  try {
    raw = (await readIngestBody(req, 64 * 1024)).value;
  } catch (e) {
    if (e instanceof IngestRejected) {
      await audit({ actor: 'enroll:anonymous', actorRole: 'none', action: 'enroll_request.rejected_input', sourceIp: ip, details: { rule: e.rule } });
      return error(e.status, e.status === 413 ? 'too_large' : 'bad_request', { rule: e.rule });
    }
    throw e;
  }
  const parsed = EnrollRequest.safeParse(raw);
  if (!parsed.success) return error(400, 'bad_request', { rule: zodRule(parsed.error) });
  const body = parsed.data;
  const header = req.headers.get('x-asa-agent-id');
  if (header && header !== body.agent.id) return error(400, 'bad_request', { rule: 'agent_id_mismatch' });
  const db = getDb();
  const identity = await hubIdentity(db);
  if (body.hub_fingerprint && body.hub_fingerprint !== identity.fingerprint) {
    return error(409, 'hub_fingerprint_mismatch', { fingerprint: identity.fingerprint });
  }
  const r = await createRequest(db, body, { sourceIp: ip, peerIp: peerIp(req) });
  if (!r.ok) return error(r.status, r.error, r.extra);
  return json(
    {
      request_id: r.row.id,
      status: r.row.status,
      auto_approved: r.row.autoApproved,
      request_code: r.row.requestCode,
      poll_interval_s: POLL_INTERVAL_S,
      expires_at: r.row.expiresAt.toISOString(),
      hub: hubInfo(identity),
    },
    r.created ? 201 : 200,
  );
}
