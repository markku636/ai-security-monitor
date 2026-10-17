// IP 外部情資的共用型別（server／client 都會 import，這裡只放型別與常數）。

export const PROVIDER_IDS = ['abuseipdb', 'greynoise', 'ipinfo', 'proxycheck', 'rdns'] as const;
export type ProviderId = (typeof PROVIDER_IDS)[number];

export type SkipReason =
  | 'no-api-key'
  | 'quota-exhausted'
  | 'timeout'
  | 'http-error'
  | 'parse-error'
  | 'disabled'
  | 'unsupported'
  | 'not-public';

export type UsageType = 'datacenter' | 'isp' | 'mobile' | 'business' | 'edu' | 'gov';

/**
 * 正規化後的欄位。undefined＝這個來源沒提供；null＝查過但沒有。
 */
export interface Profile {
  country?: string | null;
  city?: string | null;
  asn?: number | null;
  asnOrg?: string | null;
  isp?: string | null;
  domain?: string | null;
  usageType?: UsageType | null;
  isProxy?: boolean | null;
  isVpn?: boolean | null;
  isTor?: boolean | null;
  isDatacenter?: boolean | null;
  abuseScore?: number | null;
  abuseReports?: number | null;
  abuseLastReportedAt?: string | null;
  greynoiseClass?: string | null;
  greynoiseName?: string | null;
  greynoiseRiot?: boolean | null;
  proxyRisk?: number | null;
  proxyType?: string | null;
  hostname?: string | null;
  fcrdns?: boolean | null;
}

/** 某個來源最近一次查詢的結果（存在 ip_reputation.results）。 */
export interface ProviderResult {
  ok: boolean;
  reason?: SkipReason;
  detail?: string;
  fetchedAt: string;
  data?: Profile;
  raw?: unknown;
}

/** ai-security-monitor agent 的黑名單在這個 IP 上的命中（intel_hits）。 */
export interface LocalHit {
  feedId: string;
  feedName: string;
  vendor: string;
  confidence: number;
  sourceUrl: string;
}

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface ScoreReason {
  key: string;
  kind: 'feature' | 'rule';
  /** 對 0–100 分數的貢獻（規則類為 undefined）。 */
  contribution?: number;
  params?: Record<string, string | number>;
}

export interface IpScore {
  score: number;
  level: RiskLevel;
  reasons: ScoreReason[];
}

export interface ProviderView {
  id: ProviderId;
  name: string;
  /** 金鑰：required＝沒有就不能查；optional＝沒有也能查（額度較低）；none＝不需要。 */
  key: 'required' | 'optional' | 'none';
  configured: boolean;
  enabled: boolean;
  /** 按「查詢」時會不會送出這個 IP。 */
  willQuery: boolean;
  result: ProviderResult | null;
  /** 情資判斷：true＝命中、false＝查過無訊號、null＝未查詢。 */
  hit: boolean | null;
  link: string | null;
}

export interface IpIntelView {
  ip: string;
  isPublic: boolean;
  lookupsEnabled: boolean;
  queriedAt: string | null;
  providers: ProviderView[];
  localHits: LocalHit[];
  profile: Profile;
  score: IpScore | null;
}

/** 設定頁：一個來源的金鑰與額度狀態（不含明文金鑰）。 */
export interface SourceStatus {
  id: ProviderId;
  name: string;
  key: 'required' | 'optional' | 'none';
  env: string | null;
  keySource: 'env' | 'settings' | null;
  keyHint: string | null;
  enabled: boolean;
  quota: number;
  usedToday: number;
  signup: string | null;
}

export interface SourcesConfigStatus {
  lookupsEnabled: boolean;
  providers: SourceStatus[];
}

/**
 * 清單頁 IP 旁的風險圖示用：快取裡的外部情資分數（不打外部 API）。
 * private＝內網／保留位址（設計上不查）；unqueried＝還沒查過外部情資。
 */
export type IpRisk =
  | { kind: 'private' }
  | { kind: 'unqueried' }
  | { kind: 'scored'; score: number; level: RiskLevel; queriedAt: string };

/** 批次查詢外部情資：每個 IP 的結果。 */
export interface BatchLookupItem {
  ip: string;
  score: number | null;
  level: RiskLevel | null;
  /** true＝這次沒有打任何外部來源（全部用快取）。 */
  cached: boolean;
  skipped?: 'not_public' | 'duplicate';
  error?: string;
}
