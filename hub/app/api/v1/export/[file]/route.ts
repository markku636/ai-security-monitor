// CSV 匯出：/api/v1/export/{findings,agents,actions,audit}.csv
// 權限：管理員，或有 export scope 的 API token（audit 只限管理員）。
import { listActions } from '@/lib/actions/store';
import { apiAdminRead, apiRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error } from '@/lib/http';
import { listAudit, toCsv } from '@/lib/queries/admin';
import { listAgents } from '@/lib/queries/agents';
import { listFindings, parseFindingFilter, toFindingView } from '@/lib/queries/findings';

export const dynamic = 'force-dynamic';

const KINDS = ['findings', 'agents', 'actions', 'audit'] as const;
type Kind = (typeof KINDS)[number];

/** 最多匯出幾列（大於這個請用 API 分頁）。 */
const MAX_ROWS = 20_000;

async function findingsCsv(sp: URLSearchParams): Promise<string> {
  const f = parseFindingFilter(sp);
  const rows: unknown[][] = [];
  for (let offset = 0; offset < MAX_ROWS; offset += 1000) {
    const page = await listFindings({ ...f, limit: 1000, offset });
    for (const r of page.items.map(toFindingView)) {
      rows.push([r.hostname, r.severity, r.status, r.scanner, r.rule, r.title, r.indicator, r.firstSeenAt, r.lastSeenAt, r.agentId, r.findingId]);
    }
    if (page.items.length < 1000) break;
  }
  return toCsv(['hostname', 'severity', 'status', 'scanner', 'rule', 'title', 'indicator', 'first_seen', 'last_seen', 'agent_id', 'finding_id'], rows);
}

async function agentsCsv(): Promise<string> {
  const rows = (await listAgents()).map((a) => [
    a.hostname,
    a.status,
    [a.osName ?? a.osFamily, a.osVersion].filter(Boolean).join(' '),
    a.arch,
    a.version,
    a.ips.join(' '),
    a.score?.overall ?? '',
    a.score?.vulns ?? '',
    a.score?.hardening ?? '',
    a.openFindings,
    a.lastSeenAt,
    a.id,
  ]);
  return toCsv(['hostname', 'status', 'os', 'arch', 'asa_version', 'ips', 'score', 'score_vulns', 'score_hardening', 'open_findings', 'last_seen', 'agent_id'], rows);
}

async function actionsCsv(): Promise<string> {
  const rows: unknown[][] = [];
  for (let offset = 0; offset < MAX_ROWS; offset += 200) {
    const page = await listActions(getDb(), { limit: 200, offset });
    for (const a of page.items) {
      rows.push([a.createdAt, a.hostname, a.kind, JSON.stringify(a.params), a.status, a.proposedBy, a.reviewedBy, a.reason, a.id]);
    }
    if (page.items.length < 200) break;
  }
  return toCsv(['created_at', 'hostname', 'kind', 'params', 'status', 'proposed_by', 'reviewed_by', 'reason', 'action_id'], rows);
}

async function auditCsv(): Promise<string> {
  const rows = (await listAudit({ limit: 1000 })).map((r) => [r.at, r.actor, r.actorRole, r.action, r.targetType, r.targetId, r.sourceIp, r.details]);
  return toCsv(['at', 'actor', 'role', 'action', 'target_type', 'target_id', 'source_ip', 'details'], rows);
}

export async function GET(req: Request, ctx: { params: Promise<{ file: string }> }): Promise<Response> {
  const { file } = await ctx.params;
  const kind = file.replace(/\.csv$/i, '') as Kind;
  if (!(KINDS as readonly string[]).includes(kind)) return error(404, 'not_found');
  const id = kind === 'audit' ? await apiAdminRead(req) : await apiRead(req, { scope: 'export' });
  if (id instanceof Response) return id;
  const sp = new URL(req.url).searchParams;
  const body = kind === 'findings' ? await findingsCsv(sp) : kind === 'agents' ? await agentsCsv() : kind === 'actions' ? await actionsCsv() : await auditCsv();
  const stamp = new Date().toISOString().slice(0, 10);
  return new Response(body, {
    headers: {
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': `attachment; filename="asa-${kind}-${stamp}.csv"`,
      'cache-control': 'no-store',
    },
  });
}
