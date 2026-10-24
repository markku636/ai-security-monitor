// 網站掃描端認領工作（contract/webscan-claim.v1.json → webscan-job.v1.json）：只給它有裝的掃描器能跑的工作，順便記下版本與能力。
import { getDb } from '@/lib/db';
import { BodyTooLarge, error, json, readJson, sourceIp } from '@/lib/http';
import { zodRule } from '@/lib/ingest/schema';
import { ClaimRequest } from '@/lib/webscan/contract';
import { runnerAuth } from '@/lib/webscan/http';
import { claimJobs, POLL_AFTER_MS } from '@/lib/webscan/jobs';
import { touchRunner } from '@/lib/webscan/runners';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  const db = getDb();
  const who = await runnerAuth(req, db, 'claim', 30);
  if (who instanceof Response) return who;
  let raw: unknown;
  try {
    raw = await readJson(req, 64 * 1024);
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, 'bad_request');
  }
  const p = ClaimRequest.safeParse(raw);
  if (!p.success) return error(400, 'bad_request', { rule: zodRule(p.error) });
  await touchRunner(db, who, p.data, sourceIp(req));
  const jobs = await claimJobs(db, who, p.data);
  return json({ jobs, poll_after_ms: POLL_AFTER_MS, server_time: new Date().toISOString() });
}
