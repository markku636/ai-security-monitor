// Security Hub 資料表（PostgreSQL；測試用 PGlite 跑同一份 migration）。
// 雜湊一律存 hex 文字，避免 pg（Buffer）與 PGlite（Uint8Array）型別差異。
import {
  bigserial,
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
} from 'drizzle-orm/pg-core';

const ts = (name: string) => timestamp(name, { withTimezone: true });

export const sessions = pgTable(
  'sessions',
  {
    tokenHash: text('token_hash').primaryKey(),
    secretFingerprint: text('secret_fingerprint').notNull(),
    sourceIp: text('source_ip'),
    createdAt: ts('created_at').notNull().defaultNow(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
    expiresAt: ts('expires_at').notNull(),
  },
  (t) => [index('sessions_expires_idx').on(t.expiresAt)],
);

export const settings = pgTable('settings', {
  key: text('key').primaryKey(),
  value: jsonb('value').notNull(),
  updatedAt: ts('updated_at').notNull().defaultNow(),
  updatedBy: text('updated_by'),
});

export const auditLog = pgTable(
  'audit_log',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    at: ts('at').notNull().defaultNow(),
    actor: text('actor').notNull(),
    actorRole: text('actor_role').notNull(),
    action: text('action').notNull(),
    targetType: text('target_type'),
    targetId: text('target_id'),
    sourceIp: text('source_ip'),
    details: jsonb('details'),
  },
  (t) => [index('audit_log_at_idx').on(t.at), index('audit_log_target_idx').on(t.targetType, t.targetId)],
);

export type Scores = { overall: number; connections: number; exposure: number; vulns: number; hardening: number };
export type SevCounts = { critical: number; high: number; medium: number; low: number; info: number };

export const agents = pgTable(
  'agents',
  {
    id: text('id').primaryKey(),
    hostname: text('hostname').notNull(),
    osFamily: text('os_family').notNull().default(''),
    osName: text('os_name'),
    osVersion: text('os_version'),
    arch: text('arch').notNull().default(''),
    version: text('version').notNull().default(''),
    ips: jsonb('ips').$type<string[]>().notNull().default([]),
    labels: jsonb('labels').$type<Record<string, string>>().notNull().default({}),
    notes: text('notes'),
    elevated: boolean('elevated').notNull().default(false),
    partial: boolean('partial').notNull().default(false),
    acceptRemoteActions: boolean('accept_remote_actions').notNull().default(false),
    serviceMode: boolean('service_mode').notNull().default(false),
    keyIndex: integer('key_index'),
    firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
    lastHeartbeatAt: ts('last_heartbeat_at'),
    lastReportAt: ts('last_report_at'),
    lastReportId: text('last_report_id'),
    lastSnapshotAt: ts('last_snapshot_at'),
    score: jsonb('score').$type<Scores>(),
    sevCounts: jsonb('sev_counts').$type<SevCounts>().notNull().default({ critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
    openFindings: integer('open_findings').notNull().default(0),
    deletedAt: ts('deleted_at'),
  },
  (t) => [index('agents_last_seen_idx').on(t.lastSeenAt), index('agents_hostname_idx').on(t.hostname)],
);

export const reports = pgTable(
  'reports',
  {
    id: text('id').primaryKey(),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    schemaVersion: integer('schema_version').notNull(),
    startedAt: ts('started_at').notNull(),
    finishedAt: ts('finished_at').notNull(),
    receivedAt: ts('received_at').notNull().defaultNow(),
    scannersRun: jsonb('scanners_run').$type<string[]>().notNull(),
    score: jsonb('score').$type<Scores>().notNull(),
    findingsCount: integer('findings_count').notNull().default(0),
    newCount: integer('new_count').notNull().default(0),
    resolvedCount: integer('resolved_count').notNull().default(0),
    partial: boolean('partial').notNull().default(false),
    payloadBytes: integer('payload_bytes').notNull().default(0),
    payload: jsonb('payload'),
    sourceIp: text('source_ip'),
  },
  (t) => [index('reports_agent_started_idx').on(t.agentId, t.startedAt), index('reports_received_idx').on(t.receivedAt)],
);

export const findings = pgTable(
  'findings',
  {
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    findingId: text('finding_id').notNull(),
    scanner: text('scanner').notNull(),
    rule: text('rule').notNull(),
    severity: text('severity').notNull(),
    title: text('title').notNull(),
    detail: text('detail').notNull(),
    evidence: jsonb('evidence').notNull(),
    recommendation: text('recommendation').notNull().default(''),
    actions: jsonb('actions').notNull().default([]),
    intelHits: jsonb('intel_hits').notNull().default([]),
    tags: jsonb('tags').$type<string[]>().notNull().default([]),
    refs: jsonb('refs').$type<string[]>().notNull().default([]),
    /** open / acked / suppressed / resolved */
    status: text('status').notNull().default('open'),
    /** agent 端白名單條目（agent 已判定不需處理）。 */
    allowlistedBy: text('allowlisted_by'),
    firstSeenAt: ts('first_seen_at').notNull(),
    lastSeenAt: ts('last_seen_at').notNull(),
    resolvedAt: ts('resolved_at'),
    ackedAt: ts('acked_at'),
    ackedBy: text('acked_by'),
    suppressedUntil: ts('suppressed_until'),
    suppressReason: text('suppress_reason'),
    contentHash: text('content_hash').notNull(),
    firstReportId: text('first_report_id').notNull(),
    lastReportId: text('last_report_id').notNull(),
    /** 主要指標（遠端 IP / port / CVE），列表篩選用。 */
    indicator: text('indicator'),
  },
  (t) => [
    primaryKey({ columns: [t.agentId, t.findingId] }),
    index('findings_status_sev_idx').on(t.status, t.severity),
    index('findings_agent_status_idx').on(t.agentId, t.status),
    index('findings_scanner_idx').on(t.scanner),
    index('findings_indicator_idx').on(t.indicator),
    index('findings_last_seen_idx').on(t.lastSeenAt),
  ],
);

export const intelHits = pgTable(
  'intel_hits',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    findingId: text('finding_id').notNull(),
    reportId: text('report_id').notNull(),
    feedId: text('feed_id').notNull(),
    feedName: text('feed_name').notNull(),
    vendor: text('vendor').notNull(),
    license: text('license').notNull(),
    sourceUrl: text('source_url').notNull(),
    confidence: integer('confidence').notNull(),
    indicator: text('indicator').notNull(),
    fetchedAt: ts('fetched_at'),
    seenAt: ts('seen_at').notNull().defaultNow(),
  },
  (t) => [
    index('intel_hits_seen_idx').on(t.seenAt),
    index('intel_hits_indicator_idx').on(t.indicator),
    index('intel_hits_feed_seen_idx').on(t.feedId, t.seenAt),
    index('intel_hits_agent_finding_idx').on(t.agentId, t.findingId),
  ],
);

/** 每個 agent 最新一次快照的連線（每次快照整批替換）。 */
export const connections = pgTable(
  'connections',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    at: ts('at').notNull(),
    proto: text('proto').notNull(),
    localIp: text('local_ip').notNull(),
    localPort: integer('local_port').notNull(),
    remoteIp: text('remote_ip'),
    remotePort: integer('remote_port'),
    state: text('state').notNull(),
    direction: text('direction').notNull(),
    verdict: text('verdict').notNull(),
    reasons: jsonb('reasons').notNull().default([]),
    intelFeedIds: jsonb('intel_feed_ids').$type<string[]>().notNull().default([]),
    pid: integer('pid'),
    processName: text('process_name'),
    exe: text('exe'),
    country: text('country'),
    asn: integer('asn'),
    org: text('org'),
  },
  (t) => [
    index('connections_agent_idx').on(t.agentId),
    index('connections_verdict_idx').on(t.verdict),
    index('connections_remote_idx').on(t.remoteIp),
  ],
);

/** 每個 agent 看過的遠端目的地（長期彙總；「新目的地」與車隊查詢用）。 */
export const destinations = pgTable(
  'destinations',
  {
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    remoteIp: text('remote_ip').notNull(),
    remotePort: integer('remote_port').notNull(),
    direction: text('direction').notNull(),
    firstSeenAt: ts('first_seen_at').notNull(),
    lastSeenAt: ts('last_seen_at').notNull(),
    worstVerdict: text('worst_verdict').notNull(),
    processName: text('process_name'),
    country: text('country'),
    asn: integer('asn'),
    org: text('org'),
    seenCount: integer('seen_count').notNull().default(1),
  },
  (t) => [
    primaryKey({ columns: [t.agentId, t.remoteIp, t.remotePort, t.direction] }),
    index('destinations_remote_idx').on(t.remoteIp),
    index('destinations_verdict_idx').on(t.worstVerdict, t.lastSeenAt),
  ],
);
