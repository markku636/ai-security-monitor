// IP 風險分數 0–100（規則式、純函式）：各訊號加權平均，再套確定性下限。
// 權重與下限沿用 at-integration-tools 的 rule-v1，黑名單改用 ai-security-monitor agent 自己同步的清單命中。
import type { IpScore, LocalHit, Profile, RiskLevel, ScoreReason } from './types';

export const WEIGHTS = {
  spamhaus: 30,
  ipsum: 25,
  firehol: 20,
  blocklist: 20,
  tor: 10,
  abuseipdb: 25,
  greynoiseMalicious: 15,
  proxy: 12,
  datacenter: 8,
  /** 負向：GreyNoise 判定良性（已知合法掃描器、CDN、公共服務）。 */
  greynoiseBenign: 20,
} as const;

const POSITIVE = (Object.keys(WEIGHTS) as (keyof typeof WEIGHTS)[]).filter((k) => k !== 'greynoiseBenign');
const DENOM = POSITIVE.reduce((s, k) => s + WEIGHTS[k], 0);

const MAX_REASONS = 6;

export function riskLevel(score: number): RiskLevel {
  return score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
}

const contribution = (signal: number, weight: number) => +((100 * signal * weight) / DENOM).toFixed(1);

function feedKind(feedId: string): 'spamhaus' | 'ipsum' | 'firehol' | 'tor' | 'blocklist' {
  if (feedId.startsWith('spamhaus-')) return 'spamhaus';
  if (feedId === 'ipsum') return 'ipsum';
  if (feedId === 'firehol-level1') return 'firehol';
  if (feedId === 'tor-exits') return 'tor';
  return 'blocklist';
}

/**
 * 沒有任何訊號來源（沒查外部、也沒有黑名單命中）時回 null：
 * 「零命中」不等於安全，畫面要顯示「尚未查詢」而不是 0 分。
 */
export function scoreIp(profile: Profile, hits: LocalHit[], queried: boolean): IpScore | null {
  if (!queried && !hits.length) return null;
  const reasons: (ScoreReason & { contribution: number })[] = [];
  let ws = 0;
  const add = (key: string, signal: number, weight: number, params?: ScoreReason['params']) => {
    if (signal <= 0) return;
    ws += signal * weight;
    reasons.push({ key, kind: 'feature', contribution: contribution(signal, weight), params });
  };

  const kinds = new Map<string, LocalHit[]>();
  for (const h of hits) {
    const k = feedKind(h.feedId);
    kinds.set(k, [...(kinds.get(k) ?? []), h]);
  }
  const tor = kinds.has('tor') || profile.isTor === true;
  if (kinds.has('spamhaus')) add('spamhaus', 1, WEIGHTS.spamhaus);
  if (kinds.has('ipsum')) add('ipsum', 1, WEIGHTS.ipsum);
  if (kinds.has('firehol')) add('firehol', 1, WEIGHTS.firehol);
  const others = kinds.get('blocklist') ?? [];
  if (others.length) {
    const best = Math.max(...others.map((h) => h.confidence)) / 100;
    add('blocklist', Math.min(1, best), WEIGHTS.blocklist, { feeds: [...new Set(others.map((h) => h.feedName))].join('、') });
  }
  if (tor) add('tor', 1, WEIGHTS.tor);
  if (profile.abuseScore != null && profile.abuseScore > 0) {
    add('abuseipdb', profile.abuseScore / 100, WEIGHTS.abuseipdb, { score: profile.abuseScore, reports: profile.abuseReports ?? 0 });
  }
  if (profile.greynoiseClass === 'malicious') add('greynoise_malicious', 1, WEIGHTS.greynoiseMalicious);
  if (profile.isProxy || profile.isVpn) add('proxy', 1, WEIGHTS.proxy, { type: profile.proxyType ?? (profile.isVpn ? 'VPN' : 'Proxy') });
  if (profile.isDatacenter) add('datacenter', 1, WEIGHTS.datacenter);
  const benign = profile.greynoiseClass === 'benign' || profile.greynoiseRiot === true;
  if (benign) {
    ws -= WEIGHTS.greynoiseBenign;
    reasons.push({
      key: 'greynoise_benign',
      kind: 'feature',
      contribution: -contribution(1, WEIGHTS.greynoiseBenign),
      params: { name: profile.greynoiseName ?? '' },
    });
  }

  let score = Math.max(0, Math.min(100, Math.round((100 * ws) / DENOM)));
  const rules: ScoreReason[] = [];
  const floor = (key: string, when: boolean, v: number) => {
    if (when && score < v) {
      score = v;
      rules.push({ key, kind: 'rule', params: { n: v } });
    }
  };
  floor('rule_spamhaus', kinds.has('spamhaus'), 85);
  floor('rule_abuseipdb_high', (profile.abuseScore ?? 0) >= 90, 75);
  floor('rule_tor', tor, 40);

  reasons.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  return { score, level: riskLevel(score), reasons: [...rules, ...reasons].slice(0, MAX_REASONS) };
}
