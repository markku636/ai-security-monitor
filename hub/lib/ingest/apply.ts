// 寫入：註冊、報告（冪等＋finding 差異）、連線快照（整批替換＋目的地彙總）、心跳。
import crypto from 'node:crypto';
import { and, eq, inArray, ne, sql } from 'drizzle-orm';
import { agents, connections, destinations, findings, intelHits, reports, type SevCounts } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { IngestRejected } from './guard';
import type { FindingT, HeartbeatT, RegisterT, ReportT, SnapshotT } from './schema';

const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const VERDICT_RANK: Record<string, number> = { safe: 0, unknown: 1, suspicious: 2, dangerous: 3 };

type AgentInfoT = ReportT['agent'];

function agentColumns(a: AgentInfoT, now: Date) {
  return {
    hostname: a.hostname,
    osFamily: a.os.family,
    osName: a.os.name ?? null,
    osVersion: a.os.version ?? a.os.build ?? null,
    arch: a.arch,
    version: a.version,
    ips: a.ips,
    elevated: a.elevated,
    lastSeenAt: now,
  };
}

async function assertNotDeleted(db: DB, agentId: string): Promise<boolean> {
  const rows = await db.select({ deletedAt: agents.deletedAt }).from(agents).where(eq(agents.id, agentId)).limit(1);
  if (rows[0]?.deletedAt) throw new IngestRejected(410, 'agent_deleted');
  return rows.length > 0;
}

export interface RegisterResult {
  agent_id: string;
  created: boolean;
}

export async function applyRegister(db: DB, body: RegisterT, keyIndex: number | undefined): Promise<RegisterResult> {
  const now = new Date();
  const existed = await assertNotDeleted(db, body.agent.id);
  const cols = {
    ...agentColumns(body.agent, now),
    acceptRemoteActions: body.accept_remote_actions,
    serviceMode: body.service_mode,
    keyIndex: keyIndex ?? null,
  };
  await db
    .insert(agents)
    .values({ id: body.agent.id, ...cols, firstSeenAt: now })
    .onConflictDoUpdate({ target: agents.id, set: cols });
  return { agent_id: body.agent.id, created: !existed };
}

function indicatorOf(f: FindingT): string | null {
  const ev = f.evidence as Record<string, unknown>;
  switch (ev.type) {
    case 'connection':
      return typeof ev.remote_ip === 'string' ? ev.remote_ip : null;
    case 'port':
      return `${ev.proto}/${ev.port}`;
    case 'cve':
      return typeof ev.id === 'string' ? ev.id : null;
    case 'package':
      return typeof ev.name === 'string' ? ev.name : null;
    case 'flow':
      return typeof ev.remote === 'string' ? ev.remote : null;
    default:
      return null;
  }
}

function contentHash(f: FindingT): string {
  return crypto.createHash('sha256').update(JSON.stringify([f.severity, f.title, f.detail])).digest('hex').slice(0, 32);
}

export interface ReportResult {
  report_id: string;
  duplicate: boolean;
  findings: { new: number; updated: number; unchanged: number; reopened: number; resolved: number };
}

export async function applyReport(
  db: DB,
  r: ReportT,
  meta: { sourceIp: string; bytes: number; keyIndex?: number },
): Promise<ReportResult> {
  const finished = new Date(r.finished_at);
  const now = new Date();
  // 未來時間（時鐘偏差）夾到現在。
  const seenAt = finished > now ? now : finished;
  const counts = { new: 0, updated: 0, unchanged: 0, reopened: 0, resolved: 0 };

  return db.transaction(async (tx) => {
    const t = tx as unknown as DB;
    await assertNotDeleted(t, r.agent.id);
    await t
      .insert(agents)
      .values({ id: r.agent.id, ...agentColumns(r.agent, now), keyIndex: meta.keyIndex ?? null, firstSeenAt: now })
      .onConflictDoUpdate({ target: agents.id, set: agentColumns(r.agent, now) });

    const inserted = await t
      .insert(reports)
      .values({
        id: r.report_id,
        agentId: r.agent.id,
        schemaVersion: r.schema_version,
        startedAt: new Date(r.started_at),
        finishedAt: seenAt,
        scannersRun: r.scanners_run,
        score: r.score,
        findingsCount: r.findings.length,
        partial: r.partial,
        payloadBytes: meta.bytes,
        payload: r as unknown as Record<string, unknown>,
        sourceIp: meta.sourceIp,
      })
      .onConflictDoNothing()
      .returning({ id: reports.id });
    if (!inserted.length) return { report_id: r.report_id, duplicate: true, findings: counts };

    const existing = await t
      .select({
        findingId: findings.findingId,
        status: findings.status,
        severity: findings.severity,
        contentHash: findings.contentHash,
        suppressedUntil: findings.suppressedUntil,
      })
      .from(findings)
      .where(eq(findings.agentId, r.agent.id));
    const byId = new Map(existing.map((e) => [e.findingId, e]));

    const seen = new Set<string>();
    for (const f of r.findings) {
      if (seen.has(f.id)) continue;
      seen.add(f.id);
      const hash = contentHash(f);
      const common = {
        scanner: f.scanner,
        rule: f.rule,
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        evidence: f.evidence,
        recommendation: f.recommendation,
        actions: f.actions,
        intelHits: f.intel_hits,
        tags: f.tags,
        refs: f.refs,
        allowlistedBy: f.suppressed_by ?? null,
        lastSeenAt: seenAt,
        lastReportId: r.report_id,
        contentHash: hash,
        indicator: indicatorOf(f),
      };
      const ex = byId.get(f.id);
      if (!ex) {
        await t.insert(findings).values({
          agentId: r.agent.id,
          findingId: f.id,
          ...common,
          status: f.suppressed_by ? 'suppressed' : 'open',
          suppressReason: f.suppressed_by ? 'agent allowlist' : null,
          firstSeenAt: new Date(f.first_seen) > now ? now : new Date(f.first_seen),
          firstReportId: r.report_id,
        });
        counts.new++;
        continue;
      }
      let status = ex.status;
      let reopened = false;
      if (status === 'resolved') {
        status = 'open';
        reopened = true;
      } else if (status === 'acked' && (SEV_RANK[f.severity] ?? 0) > (SEV_RANK[ex.severity] ?? 0)) {
        status = 'open';
        reopened = true;
      } else if (status === 'suppressed' && ex.suppressedUntil && ex.suppressedUntil < now) {
        status = 'open';
        reopened = true;
      }
      await t
        .update(findings)
        .set({ ...common, status, ...(reopened ? { resolvedAt: null } : {}) })
        .where(and(eq(findings.agentId, r.agent.id), eq(findings.findingId, f.id)));
      if (reopened) counts.reopened++;
      else if (ex.contentHash !== hash) counts.updated++;
      else counts.unchanged++;
    }

    // 這次有跑、但沒再出現的掃描器 finding → 已解決（沒跑的掃描器不動）。
    if (r.scanners_run.length) {
      const resolved = await t
        .update(findings)
        .set({ status: 'resolved', resolvedAt: seenAt })
        .where(
          and(
            eq(findings.agentId, r.agent.id),
            inArray(findings.scanner, r.scanners_run),
            ne(findings.lastReportId, r.report_id),
            inArray(findings.status, ['open', 'acked']),
          ),
        )
        .returning({ id: findings.findingId });
      counts.resolved = resolved.length;
    }

    // 情資命中：本次出現的 finding 先清再寫（保留來源與授權）。
    const ids = [...seen];
    if (ids.length) {
      await t.delete(intelHits).where(and(eq(intelHits.agentId, r.agent.id), inArray(intelHits.findingId, ids)));
    }
    const hitRows = r.findings.flatMap((f) =>
      f.intel_hits.map((h) => ({
        agentId: r.agent.id,
        findingId: f.id,
        reportId: r.report_id,
        feedId: h.feed_id,
        feedName: h.name,
        vendor: h.vendor,
        license: h.license,
        sourceUrl: h.source_url,
        confidence: h.confidence,
        indicator: h.matched,
        fetchedAt: new Date(h.fetched_at),
        seenAt,
      })),
    );
    for (let i = 0; i < hitRows.length; i += 500) {
      await t.insert(intelHits).values(hitRows.slice(i, i + 500));
    }

    const sev = await t
      .select({ severity: findings.severity, n: sql<number>`count(*)::int` })
      .from(findings)
      .where(and(eq(findings.agentId, r.agent.id), eq(findings.status, 'open')))
      .groupBy(findings.severity);
    const sevCounts: SevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const s of sev) if (s.severity in sevCounts) sevCounts[s.severity as keyof SevCounts] = Number(s.n);
    const open = Object.values(sevCounts).reduce((a, b) => a + b, 0);

    await t
      .update(agents)
      .set({
        score: r.score,
        partial: r.partial,
        lastReportAt: now,
        lastReportId: r.report_id,
        sevCounts,
        openFindings: open,
      })
      .where(eq(agents.id, r.agent.id));
    await t
      .update(reports)
      .set({ newCount: counts.new + counts.reopened, resolvedCount: counts.resolved })
      .where(eq(reports.id, r.report_id));
    return { report_id: r.report_id, duplicate: false, findings: counts };
  });
}

const verdictRankSql = (x: unknown) =>
  sql`(case ${x} when 'dangerous' then 3 when 'suspicious' then 2 when 'unknown' then 1 else 0 end)`;

export interface SnapshotResult {
  stored: number;
  dangerous: number;
  suspicious: number;
  destinations: number;
}

export async function applySnapshot(db: DB, s: SnapshotT): Promise<SnapshotResult> {
  const at = new Date(s.ts) > new Date() ? new Date() : new Date(s.ts);
  return db.transaction(async (tx) => {
    const t = tx as unknown as DB;
    const known = await assertNotDeleted(t, s.agent_id);
    if (!known) throw new IngestRejected(409, 'register_first');
    await t.delete(connections).where(eq(connections.agentId, s.agent_id));
    const rows = s.connections.map((c) => {
      const reasons = c.verdict.reasons as Array<Record<string, unknown>>;
      return {
        agentId: s.agent_id,
        at,
        proto: c.proto,
        localIp: c.local_ip,
        localPort: c.local_port,
        remoteIp: c.remote_ip ?? null,
        remotePort: c.remote_port ?? null,
        state: c.state,
        direction: c.direction,
        verdict: c.verdict.level,
        reasons,
        intelFeedIds: reasons.filter((x) => x.type === 'intel_hit' && typeof x.feed_id === 'string').map((x) => x.feed_id as string),
        pid: c.process?.pid ?? null,
        processName: c.process?.name ?? null,
        exe: c.process?.exe ?? null,
        country: c.geo?.country ?? null,
        asn: c.geo?.asn ?? null,
        org: c.geo?.org ?? null,
      };
    });
    for (let i = 0; i < rows.length; i += 500) {
      await t.insert(connections).values(rows.slice(i, i + 500));
    }

    // 目的地彙總：同一快照內相同 (ip, port, 方向) 先合併，避免 ON CONFLICT 同列更新兩次。
    const dest = new Map<string, (typeof rows)[number]>();
    for (const r of rows) {
      if (!r.remoteIp || r.remotePort == null || (r.direction !== 'outbound' && r.direction !== 'inbound')) continue;
      const k = `${r.remoteIp}|${r.remotePort}|${r.direction}`;
      const prev = dest.get(k);
      if (!prev || (VERDICT_RANK[r.verdict] ?? 0) > (VERDICT_RANK[prev.verdict] ?? 0)) dest.set(k, r);
    }
    const destRows = [...dest.values()].map((r) => ({
      agentId: r.agentId,
      remoteIp: r.remoteIp!,
      remotePort: r.remotePort!,
      direction: r.direction,
      firstSeenAt: at,
      lastSeenAt: at,
      worstVerdict: r.verdict,
      processName: r.processName,
      country: r.country,
      asn: r.asn,
      org: r.org,
    }));
    for (let i = 0; i < destRows.length; i += 500) {
      await t
        .insert(destinations)
        .values(destRows.slice(i, i + 500))
        .onConflictDoUpdate({
          target: [destinations.agentId, destinations.remoteIp, destinations.remotePort, destinations.direction],
          set: {
            lastSeenAt: sql`excluded.last_seen_at`,
            seenCount: sql`${destinations.seenCount} + 1`,
            processName: sql`coalesce(excluded.process_name, ${destinations.processName})`,
            country: sql`coalesce(excluded.country, ${destinations.country})`,
            asn: sql`coalesce(excluded.asn, ${destinations.asn})`,
            org: sql`coalesce(excluded.org, ${destinations.org})`,
            worstVerdict: sql`case when ${verdictRankSql(sql`excluded.worst_verdict`)} > ${verdictRankSql(destinations.worstVerdict)} then excluded.worst_verdict else ${destinations.worstVerdict} end`,
          },
        });
    }
    await t.update(agents).set({ lastSnapshotAt: at, lastSeenAt: new Date() }).where(eq(agents.id, s.agent_id));
    return {
      stored: rows.length,
      dangerous: rows.filter((r) => r.verdict === 'dangerous').length,
      suspicious: rows.filter((r) => r.verdict === 'suspicious').length,
      destinations: destRows.length,
    };
  });
}

export async function applyHeartbeat(db: DB, h: HeartbeatT): Promise<boolean> {
  const known = await assertNotDeleted(db, h.agent_id);
  if (!known) return false;
  const now = new Date();
  await db
    .update(agents)
    .set({ lastHeartbeatAt: now, lastSeenAt: now, version: h.version, elevated: h.elevated })
    .where(eq(agents.id, h.agent_id));
  return true;
}
