// 管理員：建立掃描工作。範圍在這裡強制（重新解析、檢查位址、主動掃描要有效的擁有權證明或內網白名單）。
import { z } from 'zod';
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { jobErrorStatus } from '@/lib/webscan/http';
import { createScanJob, listJobs, publicJob } from '@/lib/webscan/jobs';

export const dynamic = 'force-dynamic';

const Body = z.object({
  target_id: z.string().max(64),
  profile: z.string().max(40),
  scanners: z.array(z.string().max(40)).max(16).optional(),
});

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  const target = new URL(req.url).searchParams.get('target_id') ?? undefined;
  return json({ items: await listJobs(getDb(), { targetId: target, limit: 100 }) });
}

export async function POST(req: Request): Promise<Response> {
  return adminWrite(req, async (body, actor) => {
    const b = Body.parse(body);
    const r = await createScanJob(getDb(), { targetId: b.target_id, profile: b.profile, scanners: b.scanners }, actor);
    if ('error' in r) return error(jobErrorStatus(r.error), r.error);
    await adminAudit(req, actor, 'webscan.job_created', 'web_target', b.target_id, { job: r.job.id, profile: r.job.profile, scanners: r.job.scanners });
    return json({ ok: true, job: publicJob(r.job) });
  });
}
