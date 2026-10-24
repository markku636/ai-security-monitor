// 管理員：驗證擁有權。dns-txt 由 Hub 直接查 DNS；well-known／meta 排一個驗證工作給掃描端去抓（Hub 不連目標）。
import { z } from 'zod';
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { jobErrorStatus } from '@/lib/webscan/http';
import { createVerifyJob, publicJob } from '@/lib/webscan/jobs';
import { WEBSCAN_VERIFY_METHODS } from '@/lib/webscan/scanners';
import { getTarget, verifyByDnsTxt } from '@/lib/webscan/targets';

export const dynamic = 'force-dynamic';

const Body = z.object({ method: z.enum(WEBSCAN_VERIFY_METHODS) });

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  return adminWrite(req, async (body, actor) => {
    const { method } = Body.parse(body);
    const db = getDb();
    const t = await getTarget(db, id);
    if (!t) return error(404, 'not_found');
    if (method === 'dns-txt') {
      const r = await verifyByDnsTxt(db, t);
      await adminAudit(req, actor, 'webscan.verify_checked', 'web_target', id, { method, verified: r.verified, error: r.error });
      return json({ ok: true, method, verified: r.verified, error: r.error });
    }
    const r = await createVerifyJob(db, id, method, actor);
    if ('error' in r) return error(jobErrorStatus(r.error), r.error);
    await adminAudit(req, actor, 'webscan.verify_requested', 'web_target', id, { method, job: r.job.id });
    return json({ ok: true, method, job: publicJob(r.job) });
  });
}
