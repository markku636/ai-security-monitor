// 網站掃描工作的狀態機（不用 queue 套件；runner 用 FOR UPDATE SKIP LOCKED 認領，多台 runner 搶同一池也不會重複）。
//   pending ──claim──▶ running ──results──▶ succeeded／failed
//     │ 24 小時沒人領 → expired     │ 租約 2 分鐘沒續 → 回 pending（最多 3 次，之後 failed）
//     └ 管理員取消 → cancelled      └ 管理員取消 → cancelled（runner 下一次心跳收到 cancel）
// 過期處理在每次讀寫前順手做，另外掛在 metrics 排程（lib/metrics/rollup.ts）上，不另開計時器。
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { and, desc, eq, inArray, lt, sql } from 'drizzle-orm';
import { webscanArtifacts, webscanJobs, webTargets } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { readEnv } from '@/lib/env';
import { getIntelUsage } from '@/lib/intel/usage';
import type { ArtifactMetaT, ClaimRequestT, HeartbeatBodyT, JobSpecT, JobStepT, ResultBodyT } from './contract';
import { applyScanFindings, type ApplySummary } from './findings';
import { dedupeAcrossScanners, parseArtifact, type NormalizedFinding, type ParseContext } from './parse';
import type { RunnerWho } from './runners';
import { isProfile, isScanner, SCANNER_INFO, scannersFor, type WebscanProfile, type WebscanScanner } from './scanners';
import { resolveAndScreen, type ScreenResult } from './scope';
import { getWebscanSettings, type WebscanSettingsT } from './settings';
import { getTarget, type TargetRow } from './targets';

export const LEASE_MS = 120_000;
export const PENDING_TTL_MS = 24 * 3_600_000;
export const MAX_ATTEMPTS = 3;
export const POLL_AFTER_MS = 15_000;
/** 一個 artifact 壓縮後／解壓後的上限，與一個工作全部 artifact 的上限（壓縮後）。 */
export const MAX_ARTIFACT_COMPRESSED = 8 * 1024 * 1024;
export const MAX_ARTIFACT_BYTES = 32 * 1024 * 1024;
export const MAX_JOB_ARTIFACTS_COMPRESSED = 32 * 1024 * 1024;
export const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

export type JobRow = typeof webscanJobs.$inferSelect;
type Spec = Omit<JobSpecT, 'id' | 'kind' | 'profile' | 'lease_ms' | 'deadline'>;

const newJobId = () => `wsj_${crypto.randomBytes(8).toString('hex')}`;

/** 每個掃描器在各層級的選項（runner 端再以同一份白名單檢查；dos 永遠排除）。 */
export function stepFor(s: WebscanScanner): JobStepT {
  switch (s) {
    case 'nuclei':
      return { scanner: 'nuclei', options: { exclude_tags: ['intrusive', 'dos', 'fuzz'], severities: ['info', 'low', 'medium', 'high', 'critical'] } };
    case 'testssl':
      return { scanner: 'testssl', options: { fast: false } };
    default:
      return { scanner: s, options: {} };
  }
}

/** 這個目標在這個層級實際要跑的掃描器（設定停用的、商用模式下限制商用的、第三方來源沒開的、http 網站不適用 TLS 檢查的都拿掉）。 */
export function pickScanners(t: Pick<TargetRow, 'scheme'>, profile: WebscanProfile, s: WebscanSettingsT, usage: 'commercial' | 'noncommercial', only?: string[]): WebscanScanner[] {
  return scannersFor(profile).filter(
    (x) =>
      !s.disabled_scanners.includes(x) &&
      (usage === 'noncommercial' || SCANNER_INFO[x].commercialOk) &&
      (s.third_party || !SCANNER_INFO[x].thirdParty) &&
      !(t.scheme === 'http' && (x === 'tlsx' || x === 'testssl')) &&
      (!only?.length || only.includes(x)),
  );
}

function buildSpec(t: TargetRow, screen: Extract<ScreenResult, { ok: true }>, s: WebscanSettingsT, scanners: WebscanScanner[]): Spec {
  return {
    target: { id: t.id, url: t.url, scheme: t.scheme as 'http' | 'https', host: t.host, port: t.port, path: t.path, pinned_ips: screen.ips, internal: screen.internal },
    scope: { hosts: [t.host], allowed_private_cidrs: screen.internal ? s.internal_cidrs : [] },
    limits: {
      timeout_ms: s.timeout_minutes * 60_000,
      rate_per_sec: s.rate_per_sec,
      concurrency: s.concurrency,
      max_output_bytes: MAX_OUTPUT_BYTES,
    },
    steps: scanners.map(stepFor),
    verify: null,
  };
}

async function insertJob(db: DB, row: typeof webscanJobs.$inferInsert): Promise<{ job: JobRow } | { error: 'duplicate' }> {
  try {
    const [job] = await db.insert(webscanJobs).values(row).returning();
    return { job };
  } catch {
    // 同一個目標同一種工作還在排隊或執行中（部分唯一索引）
    return { error: 'duplicate' };
  }
}

/** 建立掃描工作。由管理員手動發起，重新解析並檢查位址範圍。 */
export async function createScanJob(
  db: DB,
  input: { targetId: string; profile: string; scanners?: string[] },
  actor: string,
  now = new Date(),
): Promise<{ job: JobRow } | { error: string }> {
  await expireStaleJobs(db, now);
  const t = await getTarget(db, input.targetId);
  if (!t) return { error: 'target_not_found' };
  if (!isProfile(input.profile)) return { error: 'bad_profile' };
  if (input.scanners?.some((x) => !isScanner(x))) return { error: 'bad_scanner' };
  const s = await getWebscanSettings(db);
  const screen = await resolveAndScreen(t.host, { internalCidrs: s.internal_cidrs });
  if (!screen.ok) return { error: `blocked_target:${screen.reason}` };
  const scanners = pickScanners(t, input.profile, s, (await getIntelUsage(db)).usage, input.scanners);
  if (!scanners.length) return { error: 'no_scanners' };
  return insertJob(db, {
    id: newJobId(),
    targetId: t.id,
    kind: 'scan',
    profile: input.profile,
    scanners,
    spec: buildSpec(t, screen, s, scanners),
    requestedBy: actor,
    expiresAt: new Date(now.getTime() + PENDING_TTL_MS),
  });
}

export async function expireStaleJobs(db: DB, now = new Date()): Promise<void> {
  // Retire legacy ownership jobs on upgrade; never dispatch them to a runner.
  await db.update(webscanJobs).set({ status: 'cancelled', finishedAt: now, error: 'verification_removed' }).where(and(eq(webscanJobs.kind, 'verify'), inArray(webscanJobs.status, ['pending', 'running'])));
  const leaseOver = and(eq(webscanJobs.status, 'running'), lt(webscanJobs.leaseExpiresAt, now));
  await db.update(webscanJobs).set({ status: 'pending', runnerId: null, leaseExpiresAt: null }).where(and(leaseOver, lt(webscanJobs.attempts, MAX_ATTEMPTS)));
  await db.update(webscanJobs).set({ status: 'failed', finishedAt: now, error: 'lease_expired' }).where(leaseOver);
  await db.update(webscanJobs).set({ status: 'expired', finishedAt: now }).where(and(eq(webscanJobs.status, 'pending'), lt(webscanJobs.expiresAt, now)));
}

function toSpec(j: JobRow): JobSpecT {
  const spec = j.spec as unknown as Spec;
  const start = (j.claimedAt ?? new Date()).getTime();
  return {
    id: j.id,
    kind: j.kind as 'scan' | 'verify',
    profile: j.profile as WebscanProfile,
    lease_ms: LEASE_MS,
    deadline: new Date(start + spec.limits.timeout_ms + 60_000).toISOString(),
    ...spec,
  };
}

/** runner 認領：只給它有裝的掃描器能跑的工作；釘住的位址是 runner 自己的就不給（直接失敗）。 */
export async function claimJobs(db: DB, who: RunnerWho, c: ClaimRequestT, now = new Date()): Promise<JobSpecT[]> {
  await expireStaleJobs(db, now);
  const caps = [...new Set(c.capabilities.map((x) => x.scanner).filter(isScanner))];
  const limit = Math.min(4, Math.max(1, c.max_jobs));
  const claimed = await db.transaction(async (tx) => {
    const ids = await tx
      .select({ id: webscanJobs.id })
      .from(webscanJobs)
      .where(and(eq(webscanJobs.kind, 'scan'), eq(webscanJobs.status, 'pending'), sql`${webscanJobs.scanners} <@ ${JSON.stringify(caps)}::jsonb`))
      .orderBy(webscanJobs.createdAt)
      .limit(limit)
      .for('update', { skipLocked: true });
    if (!ids.length) return [];
    return tx
      .update(webscanJobs)
      .set({ status: 'running', runnerId: who.id, claimedAt: now, leaseExpiresAt: new Date(now.getTime() + LEASE_MS), attempts: sql`${webscanJobs.attempts} + 1` })
      .where(and(inArray(webscanJobs.id, ids.map((r) => r.id)), eq(webscanJobs.status, 'pending')))
      .returning();
  });
  const self = new Set(c.self_ips);
  const out: JobSpecT[] = [];
  for (const j of claimed) {
    const spec = toSpec(j);
    if (spec.target.pinned_ips.some((ip) => self.has(ip))) {
      await db.update(webscanJobs).set({ status: 'failed', finishedAt: now, error: 'blocked_target:self' }).where(eq(webscanJobs.id, j.id));
      continue;
    }
    out.push(spec);
  }
  return out;
}

async function ownedJob(db: DB, who: RunnerWho, id: string, allowed: string[]): Promise<JobRow | null> {
  const j = (await db.select().from(webscanJobs).where(eq(webscanJobs.id, id)).limit(1))[0];
  return j && j.runnerId === who.id && allowed.includes(j.status) ? j : null;
}

export async function heartbeatJob(db: DB, who: RunnerWho, id: string, hb: HeartbeatBodyT, now = new Date()) {
  const j = await ownedJob(db, who, id, ['running', 'cancelled']);
  if (!j) return { error: 'not_claimed' as const };
  if (j.status === 'cancelled') return { ok: true, lease_expires_at: null, cancel: true };
  const lease = new Date(now.getTime() + LEASE_MS);
  const progress = { step: hb.step ?? null, message: hb.message ?? null, progress: hb.progress ?? null, at: now.toISOString() };
  await db.update(webscanJobs).set({ leaseExpiresAt: lease, progress }).where(and(eq(webscanJobs.id, id), eq(webscanJobs.status, 'running')));
  return { ok: true, lease_expires_at: lease.toISOString(), cancel: false };
}

/** 存原始輸出（body 已解壓）。 */
export async function storeArtifact(db: DB, who: RunnerWho, id: string, meta: ArtifactMetaT, raw: Buffer) {
  const j = await ownedJob(db, who, id, ['running', 'cancelled']);
  if (!j) return { error: 'not_claimed' as const };
  if (j.kind !== 'scan' || !j.scanners.includes(meta.scanner)) return { error: 'unexpected_scanner' as const };
  const gz = zlib.gzipSync(raw);
  const [{ total }] = await db
    .select({ total: sql<number>`coalesce(sum(length(${webscanArtifacts.contentGz})), 0)::bigint` })
    .from(webscanArtifacts)
    .where(eq(webscanArtifacts.jobId, id));
  const b64 = gz.toString('base64');
  if (Number(total) + b64.length > (MAX_JOB_ARTIFACTS_COMPRESSED * 4) / 3) return { error: 'too_large' as const };
  const [row] = await db
    .insert(webscanArtifacts)
    .values({
      jobId: id,
      scanner: meta.scanner,
      format: meta.format,
      exitCode: meta.exit_code,
      durationMs: meta.duration_ms,
      truncated: meta.truncated,
      bytes: raw.length,
      sha256: crypto.createHash('sha256').update(raw).digest('hex'),
      contentGz: b64,
    })
    .returning({ id: webscanArtifacts.id });
  return { ok: true as const, artifact_id: row.id, bytes: raw.length };
}

function decompress(b64: string): string {
  return zlib.gunzipSync(Buffer.from(b64, 'base64'), { maxOutputLength: MAX_ARTIFACT_BYTES }).toString('utf8');
}

/** 解析這個工作的原始輸出：只用這次成功跑完的掃描器（失敗的不參與「已解決」判斷）。 */
async function parseJob(db: DB, j: JobRow, result: ResultBodyT, now: Date) {
  const spec = j.spec as unknown as Spec;
  const ctx: ParseContext = { url: spec.target.url, host: spec.target.host, port: spec.target.port, scheme: spec.target.scheme, now };
  const okSteps = new Set(result.steps.filter((x) => x.ok).map((x) => x.scanner));
  const arts = await db.select().from(webscanArtifacts).where(eq(webscanArtifacts.jobId, j.id)).orderBy(webscanArtifacts.id);
  const findings: NormalizedFinding[] = [];
  const warnings: string[] = [];
  const completed = new Set<string>();
  let fingerprint: Record<string, unknown> | undefined;
  for (const a of arts) {
    if (!isScanner(a.scanner) || !okSteps.has(a.scanner) || !j.scanners.includes(a.scanner)) continue;
    let text: string;
    try {
      text = decompress(a.contentGz);
    } catch {
      warnings.push(`${a.scanner}:artifact_unreadable`);
      continue;
    }
    const p = parseArtifact(a.scanner, text, ctx);
    findings.push(...p.findings);
    warnings.push(...p.warnings);
    fingerprint = p.fingerprint ?? fingerprint;
    // 截斷的輸出不完整：照樣記下看到的問題，但不拿來判斷哪些已解決
    if (!a.truncated) completed.add(a.scanner);
  }
  return { findings: dedupeAcrossScanners(findings), warnings: warnings.slice(0, 50), completed: [...completed], fingerprint };
}

/** runner 回報結束：解析原始輸出、更新發現。 */
export async function finishJob(db: DB, who: RunnerWho, id: string, result: ResultBodyT, now = new Date()) {
  const j = await ownedJob(db, who, id, ['running', 'cancelled']);
  if (!j) return { error: 'not_claimed' as const };
  const base = { finishedAt: now, leaseExpiresAt: null, result: result as unknown as Record<string, unknown> };
  if (j.status === 'cancelled') {
    await db.update(webscanJobs).set(base).where(eq(webscanJobs.id, id));
    return { ok: true, status: 'cancelled', findings: null };
  }
  const t = await getTarget(db, j.targetId);
  const p = await parseJob(db, j, result, now);
  let summary: ApplySummary | null = null;
  if (t) {
    summary = await applyScanFindings(db, t.id, j.id, p.findings, p.completed, now);
    await db
      .update(webTargets)
      .set({ lastScanAt: now, lastJobId: j.id, ...(p.fingerprint ? { fingerprint: p.fingerprint } : {}) })
      .where(eq(webTargets.id, t.id));
  }
  const status = result.ok ? 'succeeded' : 'failed';
  await db
    .update(webscanJobs)
    .set({ ...base, status, error: result.error, summary: summary ? { new: summary.new, open: summary.open, resolved: summary.resolved } : null, progress: { warnings: p.warnings } })
    .where(eq(webscanJobs.id, id));
  return { ok: true, status, findings: summary };
}

export async function cancelJob(db: DB, id: string, now = new Date()): Promise<{ job: JobRow } | { error: 'not_found' | 'bad_state' }> {
  const j = (await db.select().from(webscanJobs).where(eq(webscanJobs.id, id)).limit(1))[0];
  if (!j) return { error: 'not_found' };
  if (j.status !== 'pending' && j.status !== 'running') return { error: 'bad_state' };
  // pending 直接結束；running 等 runner 下一次心跳收到 cancel 再回報
  const [row] = await db
    .update(webscanJobs)
    .set(j.status === 'pending' ? { status: 'cancelled', finishedAt: now } : { status: 'cancelled' })
    .where(and(eq(webscanJobs.id, id), eq(webscanJobs.status, j.status)))
    .returning();
  return row ? { job: row } : { error: 'bad_state' };
}

export function publicJob(j: JobRow) {
  const spec = j.spec as unknown as Spec;
  return {
    id: j.id,
    targetId: j.targetId,
    kind: j.kind,
    profile: j.profile,
    scanners: j.scanners,
    status: j.status,
    runnerId: j.runnerId,
    attempts: j.attempts,
    pinnedIps: spec?.target?.pinned_ips ?? [],
    internal: !!spec?.target?.internal,
    progress: j.progress,
    result: j.result,
    error: j.error,
    summary: j.summary,
    requestedBy: j.requestedBy,
    createdAt: j.createdAt.toISOString(),
    claimedAt: j.claimedAt?.toISOString() ?? null,
    finishedAt: j.finishedAt?.toISOString() ?? null,
  };
}
export type JobView = ReturnType<typeof publicJob>;

export async function listJobs(db: DB, f: { targetId?: string; limit?: number } = {}) {
  await expireStaleJobs(db);
  const rows = await db
    .select()
    .from(webscanJobs)
    .where(f.targetId ? eq(webscanJobs.targetId, f.targetId) : undefined)
    .orderBy(desc(webscanJobs.createdAt))
    .limit(Math.min(f.limit ?? 50, 200));
  return rows.map(publicJob);
}

export async function getJobDetail(db: DB, id: string) {
  await expireStaleJobs(db);
  const j = (await db.select().from(webscanJobs).where(eq(webscanJobs.id, id)).limit(1))[0];
  if (!j) return null;
  const artifacts = await db
    .select({
      id: webscanArtifacts.id,
      scanner: webscanArtifacts.scanner,
      format: webscanArtifacts.format,
      exitCode: webscanArtifacts.exitCode,
      durationMs: webscanArtifacts.durationMs,
      truncated: webscanArtifacts.truncated,
      bytes: webscanArtifacts.bytes,
      sha256: webscanArtifacts.sha256,
      createdAt: webscanArtifacts.createdAt,
    })
    .from(webscanArtifacts)
    .where(eq(webscanArtifacts.jobId, id))
    .orderBy(webscanArtifacts.id);
  return { job: publicJob(j), artifacts: artifacts.map((a) => ({ ...a, createdAt: a.createdAt.toISOString() })) };
}

/** 原始輸出保留天數（`AI_SECURITY_MONITOR_HUB_WEBSCAN_ARTIFACT_DAYS`，預設 30；發現本身不會被清）。 */
export function artifactDays(): number {
  const n = Number(readEnv('ASA_HUB_WEBSCAN_ARTIFACT_DAYS') || 30);
  return Number.isFinite(n) && n >= 1 ? Math.min(3650, Math.floor(n)) : 30;
}

export async function pruneArtifacts(db: DB, now = new Date()): Promise<number> {
  const cut = new Date(now.getTime() - artifactDays() * 86_400_000);
  const r = await db.delete(webscanArtifacts).where(lt(webscanArtifacts.createdAt, cut)).returning({ id: webscanArtifacts.id });
  return r.length;
}

/** 原始輸出下載（管理員）。 */
export async function artifactContent(db: DB, artifactId: number) {
  const a = (await db.select().from(webscanArtifacts).where(eq(webscanArtifacts.id, artifactId)).limit(1))[0];
  if (!a) return null;
  return { jobId: a.jobId, scanner: a.scanner, format: a.format, text: decompress(a.contentGz) };
}
