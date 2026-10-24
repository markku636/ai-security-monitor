// Security Hub 資料表（PostgreSQL；測試用 PGlite 跑同一份 migration）。
// 雜湊一律存 hex 文字，避免 pg（Buffer）與 PGlite（Uint8Array）型別差異。
import { sql } from 'drizzle-orm';
import {
  bigint,
  bigserial,
  boolean,
  doublePrecision,
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

/** 心跳裡的更新狀態（agents.update_info）。 */
export interface AgentUpdateInfo {
  mode: string;
  owner: string;
  latest?: string | null;
  available: boolean;
  checked_at?: string | null;
  note?: string | null;
  at: string;
}

/** 心跳裡的區網廣播狀態（agents.advertising）。 */
export interface AgentAdvertising {
  url: string;
  state: string;
  fingerprint?: string | null;
  error?: string | null;
  since?: string | null;
  at: string;
}

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
    /** 最後一次收到流量／效能樣本的時間（舊版 agent 不送，一直是 null）。 */
    metricsAt: ts('metrics_at'),
    /** 這台電腦有沒有開啟效能蒐集（主機自己決定；null＝還沒送過樣本）。 */
    perfEnabled: boolean('perf_enabled'),
    /** agent 心跳回報的自動更新狀態（有沒有新版、update.mode、誰負責更新）；at＝回報時間。 */
    updateInfo: jsonb('update_info').$type<AgentUpdateInfo>(),
    /** 這台的背景服務在區網幫哪個 Hub 廣播（hub.advertise_url）；at＝回報時間，太舊就當作沒在廣播。 */
    advertising: jsonb('advertising').$type<AgentAdvertising>(),
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
    /** 最後一次被判可疑／危險的時間（之後判定變好就不再更新），可疑 IP 排名依它篩時間範圍。 */
    lastRiskyAt: ts('last_risky_at'),
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

/**
 * IP 上的網域（外部被動 DNS 反查：HackerTarget、VirusTotal、AlienVault OTX）：只有管理員在 IP 分析頁按「查詢網域」才會打外部 API。
 * 跟 ip_reputation 分開存，免得「查過網域」被當成「查過外部情資」。results：provider id → 該來源最近一次的結果。
 */
export const ipDomainLookups = pgTable(
  'ip_domain_lookups',
  {
    ip: text('ip').primaryKey(),
    results: jsonb('results').$type<Record<string, unknown>>().notNull().default({}),
    queriedAt: ts('queried_at').notNull().defaultNow(),
    queriedBy: text('queried_by'),
  },
  (t) => [index('ip_domain_lookups_queried_idx').on(t.queriedAt)],
);

/** 主機自己解析過的網域（agent 快照的 dns_names：Windows DNS 快取裡對到目前連線 IP 的名稱），保留 30 天。 */
export const ipDomains = pgTable(
  'ip_domains',
  {
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    ip: text('ip').notNull(),
    domain: text('domain').notNull(),
    firstSeenAt: ts('first_seen_at').notNull(),
    lastSeenAt: ts('last_seen_at').notNull(),
  },
  (t) => [primaryKey({ columns: [t.agentId, t.ip, t.domain] }), index('ip_domains_ip_idx').on(t.ip), index('ip_domains_seen_idx').on(t.lastSeenAt)],
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

export type MetricIface = { name: string; virtual: boolean; rx: number; tx: number };
export type MetricProcNet = { name: string; rx: number; tx: number };
export type MetricDisk = { mount: string; fs?: string; used: number; total: number; removable?: boolean };
export type MetricProcPerf = { name: string; pid?: number | null; count: number; cpu: number; rss: number };
export type MetricBattery = { percent: number; charging: boolean; plugged?: boolean | null };

/**
 * 網路流量與效能的原始樣本：每台主機每個取樣一列（預設每分鐘），保留 AI_SECURITY_MONITOR_HUB_METRICS_RAW_DAYS（預設 7 天）。
 * 網路欄位一律有；效能欄位只有主機開啟效能蒐集（perf=true）時才有。(agent_id, at) 唯一，重送不會重複計算。
 */
export const hostMetrics = pgTable(
  'host_metrics',
  {
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    at: ts('at').notNull(),
    intervalS: integer('interval_s').notNull(),
    rxBytes: bigint('rx_bytes', { mode: 'number' }).notNull().default(0),
    txBytes: bigint('tx_bytes', { mode: 'number' }).notNull().default(0),
    interfaces: jsonb('interfaces').$type<MetricIface[]>().notNull().default([]),
    /** 各程式收發量（Windows 系統管理員／macOS）；讀不到是 null。 */
    processes: jsonb('processes').$type<MetricProcNet[]>(),
    perf: boolean('perf').notNull().default(false),
    cpuPct: doublePrecision('cpu_pct'),
    cpuCores: integer('cpu_cores'),
    memUsed: bigint('mem_used', { mode: 'number' }),
    memTotal: bigint('mem_total', { mode: 'number' }),
    swapUsed: bigint('swap_used', { mode: 'number' }),
    swapTotal: bigint('swap_total', { mode: 'number' }),
    disks: jsonb('disks').$type<MetricDisk[]>(),
    /** 各磁碟區最高的使用率（%），查詢「磁碟快滿」用。 */
    diskUsedPct: doublePrecision('disk_used_pct'),
    diskRead: bigint('disk_read', { mode: 'number' }),
    diskWrite: bigint('disk_write', { mode: 'number' }),
    load1: doublePrecision('load1'),
    uptimeS: bigint('uptime_s', { mode: 'number' }),
    topCpu: jsonb('top_cpu').$type<MetricProcPerf[]>(),
    topMem: jsonb('top_mem').$type<MetricProcPerf[]>(),
    battery: jsonb('battery').$type<MetricBattery>(),
    receivedAt: ts('received_at').notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.agentId, t.at] }), index('host_metrics_at_idx').on(t.at), index('host_metrics_received_idx').on(t.receivedAt)],
);

/**
 * 每小時彙總（由 hub 背景工作從原始樣本算出，可重算、冪等），保留 AI_SECURITY_MONITOR_HUB_METRICS_HOURLY_DAYS（預設 90 天）。
 * 7 天／30 天的圖表與排行用這張表。
 */
export const hostMetricsHourly = pgTable(
  'host_metrics_hourly',
  {
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    hour: ts('hour').notNull(),
    samples: integer('samples').notNull().default(0),
    seconds: integer('seconds').notNull().default(0),
    rxBytes: bigint('rx_bytes', { mode: 'number' }).notNull().default(0),
    txBytes: bigint('tx_bytes', { mode: 'number' }).notNull().default(0),
    interfaces: jsonb('interfaces').$type<MetricIface[]>().notNull().default([]),
    processes: jsonb('processes').$type<MetricProcNet[]>(),
    perfSamples: integer('perf_samples').notNull().default(0),
    cpuAvg: doublePrecision('cpu_avg'),
    cpuMax: doublePrecision('cpu_max'),
    memUsedAvg: bigint('mem_used_avg', { mode: 'number' }),
    memUsedMax: bigint('mem_used_max', { mode: 'number' }),
    memTotal: bigint('mem_total', { mode: 'number' }),
    swapUsedMax: bigint('swap_used_max', { mode: 'number' }),
    swapTotal: bigint('swap_total', { mode: 'number' }),
    diskUsedPctMax: doublePrecision('disk_used_pct_max'),
    disks: jsonb('disks').$type<MetricDisk[]>(),
    diskRead: bigint('disk_read', { mode: 'number' }),
    diskWrite: bigint('disk_write', { mode: 'number' }),
    load1Avg: doublePrecision('load1_avg'),
    batteryMin: integer('battery_min'),
    batteryLast: integer('battery_last'),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.agentId, t.hour] }), index('host_metrics_hourly_hour_idx').on(t.hour)],
);

/**
 * DNS 查詢紀錄（agent 每分鐘聚合後上傳；保留 `AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS` 天，預設 7）。
 * 同一列重送（agent 的離線佇列）以唯一鍵覆蓋，不會重複計算。`process` 沒有時是空字串（唯一鍵不能有 null）。
 */
export const dnsQueries = pgTable(
  'dns_queries',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    /** 這一分鐘的開始。 */
    ts: ts('ts').notNull(),
    name: text('name').notNull(),
    /** 可註冊網域（eTLD+1；Hub 端簡化計算，見 lib/dns/domain.ts）。 */
    registrable: text('registrable').notNull(),
    qtype: integer('qtype').notNull(),
    rcode: text('rcode').notNull(),
    process: text('process').notNull().default(''),
    exe: text('exe'),
    count: integer('count').notNull(),
    answers: jsonb('answers').$type<string[]>().notNull().default([]),
    cnames: jsonb('cnames').$type<string[]>().notNull().default([]),
    /** etw／eventlog／cache／packet／resolved。 */
    source: text('source').notNull(),
    receivedAt: ts('received_at').notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('dns_queries_uq').on(t.agentId, t.ts, t.name, t.qtype, t.rcode, t.process, t.source),
    index('dns_queries_agent_ts_idx').on(t.agentId, t.ts),
    index('dns_queries_reg_ts_idx').on(t.registrable, t.ts),
    index('dns_queries_name_idx').on(t.name),
    index('dns_queries_ts_idx').on(t.ts),
    index('dns_queries_received_idx').on(t.receivedAt),
  ],
);

/** 每小時、每台主機、每個可註冊網域的彙總（保留 `AI_SECURITY_MONITOR_HUB_DNS_HOURLY_DAYS` 天，預設 90）。 */
export const dnsQueriesHourly = pgTable(
  'dns_queries_hourly',
  {
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    hour: ts('hour').notNull(),
    registrable: text('registrable').notNull(),
    queries: integer('queries').notNull().default(0),
    nxdomain: integer('nxdomain').notNull().default(0),
    names: integer('names').notNull().default(0),
    processes: jsonb('processes').$type<string[]>().notNull().default([]),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.agentId, t.hour, t.registrable] }),
    index('dns_hourly_reg_idx').on(t.registrable, t.hour),
    index('dns_hourly_hour_idx').on(t.hour),
  ],
);

/** 全部主機看過的可註冊網域：第一次／最後一次出現（「新出現的網域」）。 */
export const dnsDomains = pgTable(
  'dns_domains',
  {
    registrable: text('registrable').primaryKey(),
    firstSeenAt: ts('first_seen_at').notNull(),
    lastSeenAt: ts('last_seen_at').notNull(),
    firstAgentId: text('first_agent_id'),
    firstProcess: text('first_process'),
  },
  (t) => [index('dns_domains_first_idx').on(t.firstSeenAt), index('dns_domains_last_idx').on(t.lastSeenAt)],
);

/**
 * 連上 Hub 的防護 DNS 伺服器（`ai-security-monitor dns-server`），每 30 秒心跳更新狀態。
 * id：`token:<API token id>`（網頁建立的 dns 權杖）、`env`（compose 內建，ASA_HUB_DNS_TOKEN）、`agent:<agent id>`（由那台的背景服務帶起）。
 */
export const dnsServers = pgTable('dns_servers', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  agentId: text('agent_id').references(() => agents.id, { onDelete: 'set null' }),
  version: text('version').notNull().default(''),
  hostname: text('hostname').notNull().default(''),
  sourceIp: text('source_ip'),
  /** 最後一次心跳的狀態（查詢量、快取、封鎖、延遲、上游、清單）。 */
  status: jsonb('status').$type<Record<string, unknown>>().notNull().default({}),
  firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
  lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
});

/**
 * 防護 DNS 的查詢紀錄：依（用戶端, 網域, 類型, 結果）每分鐘聚合，保留 `AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS` 天。
 * agent_id＝用戶端 IP 對到的主機（對不到＝手機、IoT 這類沒裝 agent 的裝置）；rcode `BLOCKED` 時 blocked_by 是清單名稱。
 */
export const dnsResolverQueries = pgTable(
  'dns_resolver_queries',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    serverId: text('server_id')
      .notNull()
      .references(() => dnsServers.id, { onDelete: 'cascade' }),
    ts: ts('ts').notNull(),
    client: text('client').notNull(),
    agentId: text('agent_id').references(() => agents.id, { onDelete: 'set null' }),
    name: text('name').notNull(),
    registrable: text('registrable').notNull(),
    qtype: integer('qtype').notNull(),
    rcode: text('rcode').notNull(),
    blockedBy: text('blocked_by').notNull().default(''),
    count: integer('count').notNull(),
    answers: jsonb('answers').$type<string[]>().notNull().default([]),
    receivedAt: ts('received_at').notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('dns_resolver_uq').on(t.serverId, t.ts, t.client, t.name, t.qtype, t.rcode),
    index('dns_resolver_ts_idx').on(t.ts),
    index('dns_resolver_reg_ts_idx').on(t.registrable, t.ts),
    index('dns_resolver_client_ts_idx').on(t.client, t.ts),
    index('dns_resolver_rcode_ts_idx').on(t.rcode, t.ts),
  ],
);

/**
 * 通知頻道：email／slack／discord／teams／webhook／syslog。config 裡的祕密欄位（SMTP 密碼、webhook 網址、HMAC 金鑰）
 * 以 AES-256-GCM 加密存放（`enc:v1:…`），API 只回遮罩。
 */
export const notificationChannels = pgTable('notification_channels', {
  id: text('id').primaryKey(),
  kind: text('kind').notNull(),
  name: text('name').notNull(),
  config: jsonb('config').$type<Record<string, unknown>>().notNull().default({}),
  enabled: boolean('enabled').notNull().default(true),
  createdAt: ts('created_at').notNull().defaultNow(),
  createdBy: text('created_by'),
  lastOkAt: ts('last_ok_at'),
  lastError: text('last_error'),
  lastErrorAt: ts('last_error_at'),
});

/** 通知規則：什麼事件（＋條件）送到哪些頻道。只通知規則建立之後發生的事。 */
export const notificationRules = pgTable('notification_rules', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  event: text('event').notNull(),
  /** 問題事件的最低嚴重度。 */
  minSeverity: text('min_severity'),
  /** 只看這台主機（null＝全部）。 */
  agentId: text('agent_id'),
  channelIds: jsonb('channel_ids').$type<string[]>().notNull().default([]),
  /** 事件參數，例 host_offline 的 minutes、daily_digest 的 hour。 */
  params: jsonb('params').$type<Record<string, unknown>>().notNull().default({}),
  enabled: boolean('enabled').notNull().default(true),
  createdAt: ts('created_at').notNull().defaultNow(),
  createdBy: text('created_by'),
});

/** 已通知過的項目（同一規則同一件事只通知一次）。 */
export const notificationSeen = pgTable(
  'notification_seen',
  {
    ruleId: text('rule_id').notNull(),
    key: text('key').notNull(),
    at: ts('at').notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.ruleId, t.key] }), index('notification_seen_at_idx').on(t.at)],
);

/** 送出佇列與紀錄：pending → sent／failed（最多重試 3 次）。 */
export const notificationLog = pgTable(
  'notification_log',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    ruleId: text('rule_id'),
    channelId: text('channel_id').notNull(),
    event: text('event').notNull(),
    title: text('title').notNull(),
    body: text('body').notNull(),
    link: text('link'),
    status: text('status').notNull().default('pending'),
    attempts: integer('attempts').notNull().default(0),
    error: text('error'),
    createdAt: ts('created_at').notNull().defaultNow(),
    sentAt: ts('sent_at'),
  },
  (t) => [index('notification_log_status_idx').on(t.status, t.createdAt)],
);

/** 主機群組：自動回應規則可以只套用到某個群組；之後的集中設定也依群組推送。 */
export const agentGroups = pgTable('agent_groups', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  description: text('description').notNull().default(''),
  /** 集中設定（安全選項）；空＝不推送。 */
  config: jsonb('config').$type<Record<string, unknown>>().notNull().default({}),
  createdAt: ts('created_at').notNull().defaultNow(),
  createdBy: text('created_by'),
});

export const agentGroupMembers = pgTable(
  'agent_group_members',
  {
    groupId: text('group_id')
      .notNull()
      .references(() => agentGroups.id, { onDelete: 'cascade' }),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.groupId, t.agentId] }), index('agent_group_members_agent_idx').on(t.agentId)],
);

/** 自動回應規則：觸發條件 → 自動封鎖來源 IP（有到期時間）。全域開關預設關。 */
export const responseRules = pgTable('response_rules', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  /** intel_inbound／bruteforce／finding */
  trigger: text('trigger').notNull(),
  /** bruteforce 的 threshold、finding 的 rule（可結尾 *）。 */
  params: jsonb('params').$type<Record<string, unknown>>().notNull().default({}),
  blockMinutes: integer('block_minutes').notNull().default(60),
  /** 重複觸犯：第二次 ×6、第三次以後 ×24。 */
  escalate: boolean('escalate').notNull().default(true),
  groupId: text('group_id'),
  enabled: boolean('enabled').notNull().default(true),
  createdAt: ts('created_at').notNull().defaultNow(),
  createdBy: text('created_by'),
});

/** 自動封鎖紀錄：active → released（到期或手動解除）。 */
export const responseBlocks = pgTable(
  'response_blocks',
  {
    id: text('id').primaryKey(),
    ruleId: text('rule_id'),
    agentId: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    ip: text('ip').notNull(),
    reason: text('reason').notNull().default(''),
    level: integer('level').notNull().default(0),
    status: text('status').notNull().default('active'),
    blockedAt: ts('blocked_at').notNull().defaultNow(),
    expiresAt: ts('expires_at').notNull(),
    releasedAt: ts('released_at'),
    blockActionId: text('block_action_id'),
    unblockActionId: text('unblock_action_id'),
  },
  (t) => [index('response_blocks_status_idx').on(t.status, t.expiresAt), index('response_blocks_agent_ip_idx').on(t.agentId, t.ip)],
);

// ---- 網站掃描（webscan）：掃自己驗證過擁有權的網站。全新表、不掛 agents（不做假主機）。 ----

/**
 * 掃描目標：一個網址（scheme＋host＋port＋path）。主動掃描前要驗證擁有權（DNS TXT／`/.well-known` 檔／meta），
 * 或位址落在管理員設定的內網網段白名單內（verify_method＝internal-cidr）。
 */
export const webTargets = pgTable(
  'web_targets',
  {
    id: text('id').primaryKey(),
    url: text('url').notNull(),
    scheme: text('scheme').notNull(),
    host: text('host').notNull(),
    port: integer('port').notNull(),
    path: text('path').notNull().default('/'),
    name: text('name').notNull().default(''),
    verifyToken: text('verify_token').notNull(),
    /** dns-txt／well-known／meta／internal-cidr；null＝還沒驗證。 */
    verifyMethod: text('verify_method'),
    verifiedAt: ts('verified_at'),
    verifyCheckedAt: ts('verify_checked_at'),
    verifyError: text('verify_error'),
    /** 被動指紋（httpx）：狀態碼、標題、伺服器、技術。 */
    fingerprint: jsonb('fingerprint').$type<Record<string, unknown>>().notNull().default({}),
    lastScanAt: ts('last_scan_at'),
    lastJobId: text('last_job_id'),
    createdAt: ts('created_at').notNull().defaultNow(),
    createdBy: text('created_by').notNull(),
    deletedAt: ts('deleted_at'),
  },
  (t) => [uniqueIndex('web_targets_url_uq').on(t.url).where(sql`deleted_at is null`), index('web_targets_host_idx').on(t.host)],
);

/** 掃描端（webscan runner）：比照 dns_servers，online 在讀取時依 last_seen_at 算。 */
export const webscanRunners = pgTable('webscan_runners', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  version: text('version').notNull().default(''),
  hostname: text('hostname').notNull().default(''),
  sourceIp: text('source_ip'),
  capabilities: jsonb('capabilities').$type<{ scanner: string; version: string; templates?: string }[]>().notNull().default([]),
  selfIps: jsonb('self_ips').$type<string[]>().notNull().default([]),
  firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
  lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
});

/**
 * 掃描工作：pending ──runner 認領──▶ running ──results──▶ succeeded／failed
 *            │ 24 小時沒人領 → expired       │ 租約過期沒續 → 回 pending（最多 3 次，之後 failed）
 *            └ 管理員取消 → cancelled（running 的會在下一次心跳收到 cancel）
 * spec＝交給 runner 的完整內容（目標、釘住的位址、範圍、限制、步驟），runner 不得更改。
 */
export const webscanJobs = pgTable(
  'webscan_jobs',
  {
    id: text('id').primaryKey(),
    targetId: text('target_id')
      .notNull()
      .references(() => webTargets.id, { onDelete: 'cascade' }),
    /** scan／verify */
    kind: text('kind').notNull(),
    /** passive／active_light */
    profile: text('profile').notNull(),
    scanners: jsonb('scanners').$type<string[]>().notNull().default([]),
    spec: jsonb('spec').$type<Record<string, unknown>>().notNull(),
    status: text('status').notNull().default('pending'),
    runnerId: text('runner_id'),
    attempts: integer('attempts').notNull().default(0),
    leaseExpiresAt: ts('lease_expires_at'),
    progress: jsonb('progress').$type<Record<string, unknown>>().notNull().default({}),
    result: jsonb('result').$type<Record<string, unknown>>(),
    error: text('error'),
    summary: jsonb('summary').$type<{ new: number; open: number; resolved: number }>(),
    requestedBy: text('requested_by').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
    claimedAt: ts('claimed_at'),
    finishedAt: ts('finished_at'),
    expiresAt: ts('expires_at').notNull(),
  },
  (t) => [
    index('webscan_jobs_status_created_idx').on(t.status, t.createdAt),
    index('webscan_jobs_target_created_idx').on(t.targetId, t.createdAt),
    uniqueIndex('webscan_jobs_open_unique')
      .on(t.targetId, t.kind, t.profile)
      .where(sql`status in ('pending', 'running')`),
  ],
);

/** 掃描器的原始輸出（保留起來，解析器改進後可以重新解析）：gzip 後 base64 存文字（pg 與 PGlite 的 bytea 型別不同）。 */
export const webscanArtifacts = pgTable(
  'webscan_artifacts',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    jobId: text('job_id')
      .notNull()
      .references(() => webscanJobs.id, { onDelete: 'cascade' }),
    scanner: text('scanner').notNull(),
    /** jsonl／json／txt */
    format: text('format').notNull(),
    exitCode: integer('exit_code'),
    durationMs: integer('duration_ms'),
    truncated: boolean('truncated').notNull().default(false),
    /** 解壓後的位元組數。 */
    bytes: integer('bytes').notNull(),
    sha256: text('sha256').notNull(),
    contentGz: text('content_gz').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [index('webscan_artifacts_job_idx').on(t.jobId)],
);

/** 網站掃描找到的問題：同一個目標以 finding_id（掃描器＋規則＋位置的雜湊）去重；重掃沒再出現就 resolved。 */
export const webFindings = pgTable(
  'web_findings',
  {
    targetId: text('target_id')
      .notNull()
      .references(() => webTargets.id, { onDelete: 'cascade' }),
    findingId: text('finding_id').notNull(),
    scanner: text('scanner').notNull(),
    rule: text('rule').notNull(),
    severity: text('severity').notNull(),
    title: text('title').notNull(),
    detail: text('detail').notNull().default(''),
    recommendation: text('recommendation').notNull().default(''),
    /** { url, host, port, param } */
    location: jsonb('location').$type<Record<string, unknown>>().notNull().default({}),
    evidence: jsonb('evidence').$type<Record<string, unknown>>().notNull().default({}),
    cve: text('cve'),
    cwe: jsonb('cwe').$type<string[]>().notNull().default([]),
    cvss: doublePrecision('cvss'),
    refs: jsonb('refs').$type<string[]>().notNull().default([]),
    tags: jsonb('tags').$type<string[]>().notNull().default([]),
    /** open／acked／suppressed／resolved */
    status: text('status').notNull().default('open'),
    firstSeenAt: ts('first_seen_at').notNull(),
    lastSeenAt: ts('last_seen_at').notNull(),
    resolvedAt: ts('resolved_at'),
    ackedAt: ts('acked_at'),
    ackedBy: text('acked_by'),
    suppressedUntil: ts('suppressed_until'),
    suppressReason: text('suppress_reason'),
    contentHash: text('content_hash').notNull(),
    firstJobId: text('first_job_id').notNull(),
    lastJobId: text('last_job_id').notNull(),
    /** finding_id 的演算法版本（解析器改版改了 id 時用來辨認）。 */
    fingerprintVer: integer('fingerprint_ver').notNull().default(1),
  },
  (t) => [
    primaryKey({ columns: [t.targetId, t.findingId] }),
    index('web_findings_status_sev_idx').on(t.status, t.severity),
    index('web_findings_scanner_idx').on(t.scanner),
    index('web_findings_cve_idx').on(t.cve),
  ],
);
