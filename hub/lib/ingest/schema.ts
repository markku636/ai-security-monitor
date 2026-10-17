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
    // Windows（0.2.0 起）：workstation | server | domain_controller；Client | Server | Server Core；EditionID
    product_type: shortText(32).nullish(),
    installation_type: shortText(32).nullish(),
    edition: shortText(64).nullish(),
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
    // 連線 IP → 主機解析過的網域（Windows DNS 快取；舊版 agent 不送）
    dns_names: z
      .record(shortText(64), z.array(shortText(253)).max(20))
      .refine((v) => Object.keys(v).length <= 5000, { message: 'too many dns_names' })
      .optional(),
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
    intel_checked_at: isoDate.nullish(),
    intel_feeds: z.object({ ok: z.number().int().nonnegative().max(1000), total: z.number().int().nonnegative().max(1000), source: shortText(16).optional() }).nullish(),
    // 0.4.0 起：自動更新狀態、區網廣播狀態（舊版 agent 不送）
    update: z
      .object({
        mode: shortText(16),
        owner: shortText(16),
        latest: shortText(64).nullish(),
        available: z.boolean().default(false),
        checked_at: isoDate.nullish(),
        note: shortText(500).nullish(),
      })
      .passthrough()
      .nullish(),
    advertising: z
      .object({
        url: shortText(500),
        state: shortText(32),
        fingerprint: shortText(64).nullish(),
        error: shortText(500).nullish(),
        since: isoDate.nullish(),
      })
      .passthrough()
      .nullish(),
  })
  .passthrough();

// ---- 網路流量與效能樣本（POST /api/v1/ingest/metrics；contract/metrics.v1.json）----
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

export const MetricIface = z
  .object({ name: shortText(64), virtual: z.boolean().default(false), rx_bytes: count, tx_bytes: count })
  .passthrough();
export const MetricProcNet = z.object({ name: shortText(80), rx_bytes: count, tx_bytes: count }).passthrough();
export const MetricDisk = z
  .object({ mount: shortText(120), fs: shortText(32).optional(), used: count, total: count, removable: z.boolean().optional() })
  .passthrough();
export const MetricProcPerf = z
  .object({
    name: shortText(80),
    pid: z.number().int().nonnegative().nullish(),
    count: z.number().int().min(1).max(1_000_000).default(1),
    cpu_pct: z.number().min(0).max(100),
    rss: count,
  })
  .passthrough();
export const MetricPerf = z
  .object({
    cpu_pct: z.number().min(0).max(100),
    cpu_cores: z.number().int().min(1).max(8192),
    mem_used: count,
    mem_total: count,
    swap_used: count,
    swap_total: count,
    disks: z.array(MetricDisk).max(32).default([]),
    disk_read_bytes: count.nullish(),
    disk_write_bytes: count.nullish(),
    load: z.array(z.number().min(0).max(1_000_000)).length(3).nullish(),
    uptime_s: count,
    boot_time: isoDate,
    top_cpu: z.array(MetricProcPerf).max(10).default([]),
    top_mem: z.array(MetricProcPerf).max(10).default([]),
    battery: z
      .object({ percent: z.number().int().min(0).max(100), charging: z.boolean(), plugged: z.boolean().nullish() })
      .passthrough()
      .nullish(),
  })
  .passthrough();
export const MetricSample = z
  .object({
    ts: isoDate,
    interval_s: z.number().int().min(1).max(86_400),
    net: z
      .object({
        rx_bytes: count,
        tx_bytes: count,
        interfaces: z.array(MetricIface).max(32).default([]),
        processes: z.array(MetricProcNet).max(20).nullish(),
        process_source: shortText(16).nullish(),
      })
      .passthrough(),
    perf: MetricPerf.nullish(),
  })
  .passthrough();
/** 一次最多幾個樣本（agent 每批送 120 個）。 */
export const MAX_METRIC_SAMPLES = 240;
export const MetricsBatch = z
  .object({
    agent_id: AgentInfo.shape.id,
    /** 主機有沒有開啟效能蒐集（Hub 無法從遠端開）。 */
    performance: z.boolean().default(false),
    samples: z.array(MetricSample).min(1).max(MAX_METRIC_SAMPLES),
  })
  .passthrough();

/** DNS 查詢紀錄（agent 每分鐘聚合；`contract/dns.v1.json`）。 */
export const DnsRecordIn = z
  .object({
    ts: isoDate,
    name: shortText(253).min(1),
    registrable: shortText(253).nullish(),
    qtype: z.number().int().min(0).max(65_535),
    rcode: shortText(16),
    process: shortText(260).nullish(),
    exe: shortText(1024).nullish(),
    pid: z.number().int().nonnegative().nullish(),
    count: z.number().int().min(1).max(10_000_000),
    answers: z.array(shortText(64)).max(16).default([]),
    cnames: z.array(shortText(253)).max(8).default([]),
    source: shortText(16),
  })
  .passthrough();
/** 一次最多幾列（agent 每批送 500 列）。 */
export const MAX_DNS_RECORDS = 1000;
export const DnsBatch = z
  .object({
    agent_id: AgentInfo.shape.id,
    records: z.array(DnsRecordIn).min(1).max(MAX_DNS_RECORDS),
  })
  .passthrough();
export type DnsBatchT = z.infer<typeof DnsBatch>;

export type ReportT = z.infer<typeof Report>;
export type MetricsBatchT = z.infer<typeof MetricsBatch>;
export type MetricSampleT = z.infer<typeof MetricSample>;
export type FindingT = z.infer<typeof Finding>;
export type SnapshotT = z.infer<typeof Snapshot>;
export type RegisterT = z.infer<typeof Register>;
export type HeartbeatT = z.infer<typeof Heartbeat>;

/** zod 錯誤 → 簡短規則名（path），不回內容。 */
export function zodRule(err: z.ZodError): string {
  const first = err.issues[0];
  return first ? `invalid:${first.path.join('.') || '(root)'}` : 'invalid';
}
