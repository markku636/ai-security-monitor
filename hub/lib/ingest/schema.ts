// agent 上傳格式（與 agent/src/model/*.rs 對應；contract/*.v1.json 是兩邊共同的範例，測試會驗證）。
// 未知欄位一律保留（passthrough）——agent 新版多送的欄位不該讓舊 hub 拒收。
import { z } from 'zod';

const id = z.string().regex(/^[A-Za-z0-9_.:-]{1,160}$/);
const isoDate = z.string().datetime({ offset: true });
const shortText = (n: number) => z.string().max(n);

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export const Severity = z.enum(SEVERITIES);
export const VERDICTS = ['safe', 'unknown', 'suspicious', 'dangerous'] as const;
export const VerdictLevel = z.enum(VERDICTS);
export const Direction = z.enum(['outbound', 'inbound', 'listening', 'local']);

export const OsInfo = z
  .object({
    family: shortText(32),
    name: shortText(128).nullish(),
    version: shortText(128).nullish(),
    build: shortText(128).nullish(),
    kernel: shortText(128).nullish(),
  })
  .passthrough();

export const AgentInfo = z
  .object({
    id: z.string().regex(/^[A-Za-z0-9_.-]{1,128}$/),
    version: shortText(64),
    hostname: shortText(255),
    os: OsInfo,
    arch: shortText(32),
    ips: z.array(shortText(64)).max(64).default([]),
    uptime_s: z.number().int().nonnegative().nullish(),
    elevated: z.boolean().default(false),
    scanners_available: z.array(shortText(32)).max(32).default([]),
  })
  .passthrough();

export const IntelHit = z
  .object({
    feed_id: z.string().regex(/^[a-z0-9-]{1,64}$/),
    name: shortText(200),
    vendor: shortText(200),
    confidence: z.number().int().min(0).max(100),
    license: shortText(200),
    license_url: shortText(1000),
    attribution_required: z.boolean().default(false),
    fetched_at: isoDate,
    source_url: z.string().url().max(1000),
    matched: shortText(200),
    extra: z.unknown().optional(),
  })
  .passthrough();

export const ProposedAction = z
  .object({
    kind: z.string().regex(/^[a-z_]{1,40}$/),
    params: z.record(z.string(), z.unknown()),
    requires_elevation: z.boolean(),
    destructive: z.boolean(),
    reversible: z.boolean(),
    description: shortText(500),
  })
  .passthrough();

export const Evidence = z.object({ type: z.string().max(32) }).passthrough();

export const Finding = z
  .object({
    id,
    scanner: z.string().regex(/^[a-z_]{1,32}$/),
    rule: z.string().regex(/^[a-z0-9_.:-]{1,120}$/),
    severity: Severity,
    title: shortText(500),
    detail: shortText(4000),
    evidence: Evidence,
    intel_hits: z.array(IntelHit).max(50).default([]),
    recommendation: shortText(2000).default(''),
    actions: z.array(ProposedAction).max(10).default([]),
    first_seen: isoDate,
    last_seen: isoDate,
    suppressed_by: shortText(64).nullish(),
    tags: z.array(shortText(32)).max(20).default([]),
    refs: z.array(shortText(1000)).max(20).default([]),
  })
  .passthrough();

export const Scores = z.object({
  overall: z.number().int().min(0).max(100),
  connections: z.number().int().min(0).max(100),
  exposure: z.number().int().min(0).max(100),
  vulns: z.number().int().min(0).max(100),
  hardening: z.number().int().min(0).max(100),
});

export const Report = z
  .object({
    schema_version: z.literal(1),
    report_id: z.string().regex(/^[A-Za-z0-9-]{8,64}$/),
    agent: AgentInfo,
    started_at: isoDate,
    finished_at: isoDate,
    scanners_run: z.array(z.string().regex(/^[a-z_]{1,32}$/)).max(16),
    warnings: z.array(shortText(1000)).max(200).default([]),
    findings: z.array(Finding).max(5000),
    inventory: z.record(z.string(), z.unknown()).default({}),
    summaries: z.record(z.string(), z.unknown()).default({}),
    baseline: z.record(z.string(), z.unknown()).nullish(),
    score: Scores,
    partial: z.boolean().default(false),
  })
  .passthrough();

export const ProcessRef = z
  .object({
    pid: z.number().int().nonnegative(),
    name: shortText(260),
    exe: shortText(1024).nullish(),
    cmdline: shortText(1024).nullish(),
    parent_pid: z.number().int().nonnegative().nullish(),
    user: shortText(128).nullish(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/).nullish(),
  })
  .passthrough();

export const Reason = z.object({ type: z.string().max(32) }).passthrough();

export const Connection = z
  .object({
    proto: z.enum(['tcp', 'udp']),
    local_ip: shortText(64),
    local_port: z.number().int().min(0).max(65535),
    remote_ip: shortText(64).nullish(),
    remote_port: z.number().int().min(0).max(65535).nullish(),
    state: shortText(32),
    direction: Direction,
    process: ProcessRef.nullish(),
    geo: z
      .object({ country: shortText(8).nullish(), asn: z.number().int().nullish(), org: shortText(200).nullish() })
      .passthrough()
      .nullish(),
    verdict: z.object({ level: VerdictLevel, reasons: z.array(Reason).max(30).default([]) }).passthrough(),
    bytes_in: z.number().int().nonnegative().nullish(),
    bytes_out: z.number().int().nonnegative().nullish(),
  })
  .passthrough();

export const Listener = z
  .object({
    proto: z.enum(['tcp', 'udp']),
    bind_ip: shortText(64),
    port: z.number().int().min(0).max(65535),
    process: ProcessRef.nullish(),
    exposed: z.boolean(),
    reachability: z.object({ state: z.string().max(32) }).passthrough().nullish(),
  })
  .passthrough();

export const Snapshot = z
  .object({
    agent_id: AgentInfo.shape.id,
    ts: isoDate,
    connections: z.array(Connection).max(5000),
    listeners: z.array(Listener).max(2000).default([]),
  })
  .passthrough();

export const Register = z
  .object({
    agent: AgentInfo,
    accept_remote_actions: z.boolean().default(false),
    service_mode: z.boolean().default(false),
  })
  .passthrough();

export const Heartbeat = z
  .object({
    agent_id: AgentInfo.shape.id,
    ts: isoDate,
    version: shortText(64),
    uptime_s: z.number().int().nonnegative().nullish(),
    last_scan_at: isoDate.nullish(),
    elevated: z.boolean().default(false),
  })
  .passthrough();

export type ReportT = z.infer<typeof Report>;
export type FindingT = z.infer<typeof Finding>;
export type SnapshotT = z.infer<typeof Snapshot>;
export type RegisterT = z.infer<typeof Register>;
export type HeartbeatT = z.infer<typeof Heartbeat>;

/** zod 錯誤 → 簡短規則名（path），不回內容。 */
export function zodRule(err: z.ZodError): string {
  const first = err.issues[0];
  return first ? `invalid:${first.path.join('.') || '(root)'}` : 'invalid';
}
