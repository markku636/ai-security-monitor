// 管理員：單一掃描工作（狀態、結果、原始輸出清單）與取消。
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { jobErrorStatus } from '@/lib/webscan/http';
import { cancelJob, getJobDetail, publicJob } from '@/lib/webscan/jobs';

export const dynamic = 'force-dynamic';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const who = await apiAdminRead(req);
  if (who instanceof Response) return who;
  const { id } = await ctx.params;
  const d = await getJobDetail(getDb(), id);
  return d ? json(d) : error(404, 'not_found');
}

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  return adminWrite(
    req,
    async (_body, actor) => {
      const r = await cancelJob(getDb(), id);
      if ('error' in r) return error(jobErrorStatus(r.error), r.error);
      await adminAudit(req, actor, 'webscan.job_cancelled', 'webscan_job', id);
      return json({ ok: true, job: publicJob(r.job) });
    },
    { body: false },
  );
}
