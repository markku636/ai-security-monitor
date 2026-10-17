// Security Hub 資料表（PostgreSQL；測試用 PGlite 跑同一份 migration）。
// 雜湊一律存 hex 文字，避免 pg（Buffer）與 PGlite（Uint8Array）型別差異。
import { sql } from 'drizzle-orm';
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
  uniqueIndex,
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

/** API token（唯讀）：`asa_<8hex>_<40hex>`，只存 sha256；scope：read（API）、export（CSV）、mcp。 */
export const apiTokens = pgTable(
  'api_tokens',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    tokenHash: text('token_hash').notNull(),
    scopes: jsonb('scopes').$type<string[]>().notNull().default([]),
    createdAt: ts('created_at').notNull().defaultNow(),
    createdBy: text('created_by').notNull(),
    expiresAt: ts('expires_at'),
    lastUsedAt: ts('last_used_at'),
    revokedAt: ts('revoked_at'),
  },
  (t) => [index('api_tokens_created_idx').on(t.createdAt)],
);

/** 註冊金鑰（agent 上傳用，等同 client 金鑰但可在網頁建立／撤銷）：`asa_ek_<8hex>_<40hex>`，只存 sha256。 */
export const enrollKeys = pgTable(
  'enroll_keys',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    keyHash: text('key_hash').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
    createdBy: text('created_by').notNull(),
    lastUsedAt: ts('last_used_at'),
    revokedAt: ts('revoked_at'),
    /** 免金鑰加入核准後發的金鑰只給那一台 agent 用；拿去替別的 agent id 上傳一律 403。 */
    boundAgentId: text('bound_agent_id'),
  },
  (t) => [index('enroll_keys_created_idx').on(t.createdAt)],
);

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
    /** 用哪把註冊金鑰（enroll_keys.id）上傳；撤銷金鑰時可以看到會影響哪些主機。 */
    enrollKeyId: text('enroll_key_id'),
    firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
    lastHeartbeatAt: ts('last_heartbeat_at'),
    lastReportAt: ts('last_report_at'),
    lastReportId: text('last_report_id'),
    lastSnapshotAt: ts('last_snapshot_at'),
    /** agent 心跳回報：情資清單最後一次檢查／下載的時間（看各主機情資新不新）。 */
    intelCheckedAt: ts('intel_checked_at'),
    /** 情資來源：有資料的數量／應有數量。 */
    intelFeeds: jsonb('intel_feeds').$type<{ ok: number; total: number; source?: string }>(),
    score: jsonb('score').$type<Scores>(),
    sevCounts: jsonb('sev_counts').$type<SevCounts>().notNull().default({ critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
    openFindings: integer('open_findings').notNull().default(0),
    deletedAt: ts('deleted_at'),
    /** 身分釘選：第一次看到時記下 X-ASA-Agent-Token 的 sha256，之後不符就拒絕（防共用 client 金鑰冒名）。 */
    tokenHash: text('token_hash'),
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

/**
 * 遠端動作（封鎖 IP、關 port…）：pending → approved → dispatched → succeeded／failed；也可 rejected／cancelled／expired。
 * 核准後 hub 用 per-agent 金鑰簽 HMAC token，agent 驗證通過才執行。
 */
export const actions = pgTable(
  'actions',
  {
    id: text('id').primaryKey(),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    findingId: text('finding_id'),
    kind: text('kind').notNull(),
    params: jsonb('params').$type<Record<string, unknown>>().notNull(),
    paramsHash: text('params_hash').notNull(),
    reason: text('reason').notNull().default(''),
    destructive: boolean('destructive').notNull().default(false),
    requiresElevation: boolean('requires_elevation').notNull().default(true),
    /** agent／admin:<via>／ai:<run> */
    proposedBy: text('proposed_by').notNull(),
    status: text('status').notNull().default('pending'),
    createdAt: ts('created_at').notNull().defaultNow(),
    reviewedBy: text('reviewed_by'),
    reviewedAt: ts('reviewed_at'),
    reviewNote: text('review_note'),
    /** pending：等候審核的期限；approved 之後：token 有效期限。 */
    expiresAt: ts('expires_at').notNull(),
    dispatchedAt: ts('dispatched_at'),
    completedAt: ts('completed_at'),
    resultOk: boolean('result_ok'),
    resultOutput: text('result_output'),
  },
  (t) => [
    index('actions_agent_status_idx').on(t.agentId, t.status),
    index('actions_status_created_idx').on(t.status, t.createdAt),
    uniqueIndex('actions_open_unique')
      .on(t.agentId, t.kind, t.paramsHash)
      .where(sql`status in ('pending', 'approved', 'dispatched')`),
  ],
);

/** agent 回報的當機紀錄（藍屏、非預期關機、程式當掉…）；同一筆以 dedupe_key 去重。 */
export const crashRecords = pgTable(
  'crash_records',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    time: ts('time').notNull(),
    kind: text('kind').notNull(),
    code: text('code'),
    name: text('name'),
    module: text('module'),
    process: text('process'),
    details: jsonb('details').$type<Record<string, unknown>>().notNull().default({}),
    dedupeKey: text('dedupe_key').notNull(),
    receivedAt: ts('received_at').notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('crash_records_dedupe').on(t.agentId, t.dedupeKey),
    index('crash_records_time_idx').on(t.time),
    index('crash_records_agent_time_idx').on(t.agentId, t.time),
    index('crash_records_kind_code_idx').on(t.kind, t.code),
  ],
);

/** 資安事件規則的彙總（暴力破解、新帳號、新服務…）；同規則＋同對象一列，隨報告更新次數與時間。 */
export const securityEvents = pgTable(
  'security_events',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    rule: text('rule').notNull(),
    severity: text('severity').notNull(),
    count: integer('count').notNull().default(1),
    firstAt: ts('first_at').notNull(),
    lastAt: ts('last_at').notNull(),
    sourceIp: text('source_ip'),
    userName: text('user_name'),
    detail: text('detail').notNull().default(''),
    intel: jsonb('intel').notNull().default([]),
    dedupeKey: text('dedupe_key').notNull(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('security_events_dedupe').on(t.agentId, t.dedupeKey),
    index('security_events_rule_last_idx').on(t.rule, t.lastAt),
    index('security_events_source_idx').on(t.sourceIp),
  ],
);

/** 每台 agent 最新的引擎摘要（events／traffic），整份 JSON 原樣保存給頁面與 AI 用。 */
export const agentSummaries = pgTable(
  'agent_summaries',
  {
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull(),
    at: ts('at').notNull(),
    summary: jsonb('summary').$type<Record<string, unknown>>().notNull(),
  },
  (t) => [primaryKey({ columns: [t.agentId, t.kind] })],
);

/** AI 分析紀錄（hub 上執行 Claude Code／Codex 的每一輪）。 */
export const aiAnalyses = pgTable(
  'ai_analyses',
  {
    id: text('id').primaryKey(),
    createdAt: ts('created_at').notNull().defaultNow(),
    finishedAt: ts('finished_at'),
    provider: text('provider').notNull(),
    scope: text('scope').notNull(),
    agentId: text('agent_id'),
    prompt: text('prompt').notNull(),
    /** running / done / error / cancelled */
    status: text('status').notNull().default('running'),
    resultText: text('result_text'),
    toolsCalled: integer('tools_called').notNull().default(0),
    events: jsonb('events').$type<unknown[]>().notNull().default([]),
    error: text('error'),
    createdBy: text('created_by').notNull(),
  },
  (t) => [index('ai_analyses_created_idx').on(t.createdAt)],
);

/**
 * IP 外部情資快取（AbuseIPDB、GreyNoise、ipinfo、proxycheck、反解）：只有管理員在 IP 分析頁按「查詢」才會打外部 API。
 * results：provider id → 該來源最近一次的結果（含原始回應與時間）。
 */
export const ipReputation = pgTable(
  'ip_reputation',
  {
    ip: text('ip').primaryKey(),
    results: jsonb('results').$type<Record<string, unknown>>().notNull().default({}),
    queriedAt: ts('queried_at').notNull().defaultNow(),
    queriedBy: text('queried_by'),
  },
  (t) => [index('ip_reputation_queried_idx').on(t.queriedAt)],
);

/** 管理員對遠端 IP 的人工備註（例如「公司 VPN，已確認」）；一個 IP 一則，清空即刪除。 */
export const ipNotes = pgTable('ip_notes', {
  ip: text('ip').primaryKey(),
  note: text('note').notNull(),
  updatedAt: ts('updated_at').notNull().defaultNow(),
  updatedBy: text('updated_by'),
});

/**
 * 免金鑰加入申請：agent 帶一組隨機 request_secret 來申請（只存 sha256），管理員在「新增主機」頁核准／拒絕，
 * 或來源 IP 在自動核准網段內就直接核准。核准後 agent 輪詢拿到一把只綁這台 agent 的註冊金鑰（不存明文，HMAC 衍生）。
 * pending → approved（→ claimed_at）／rejected／expired。
 */
export const enrollmentRequests = pgTable(
  'enrollment_requests',
  {
    id: text('id').primaryKey(),
    agentId: text('agent_id').notNull(),
    hostname: text('hostname').notNull(),
    osFamily: text('os_family'),
    osName: text('os_name'),
    osVersion: text('os_version'),
    arch: text('arch'),
    agentVersion: text('agent_version'),
    ips: jsonb('ips').$type<string[]>().notNull().default([]),
    agent: jsonb('agent').$type<Record<string, unknown>>(),
    acceptRemoteActions: boolean('accept_remote_actions').notNull().default(false),
    secretHash: text('secret_hash').notNull(),
    requestCode: text('request_code').notNull(),
    sourceIp: text('source_ip'),
    status: text('status').notNull().default('pending'),
    autoApproved: boolean('auto_approved').notNull().default(false),
    reason: text('reason'),
    createdAt: ts('created_at').notNull().defaultNow(),
    decidedAt: ts('decided_at'),
    decidedBy: text('decided_by'),
    expiresAt: ts('expires_at').notNull(),
    claimedAt: ts('claimed_at'),
    enrollKeyId: text('enroll_key_id'),
  },
  (t) => [index('enrollment_requests_status_idx').on(t.status, t.createdAt), index('enrollment_requests_agent_idx').on(t.agentId)],
);
