// 網站掃描的狀態文字與錯誤碼白話說明（沒有 hook：server／client 元件都能用）。
import type { TFn } from '@/lib/i18n/core';

export function profileLabel(t: TFn, p: string): string {
  return p === 'active_light' ? t('主動掃描') : p === 'passive' ? t('被動檢查') : p;
}

export function profileHint(t: TFn, p: string): string {
  return p === 'active_light'
    ? t('會送出探測請求找已知漏洞與設定問題（不做注入、不做 DoS、不做模糊測試）；要先證明網站是你的，或位址在內網白名單裡。')
    : t('只做跟一般瀏覽器差不多的幾個請求：看憑證、標頭與網站用了哪些技術。網站還沒驗證也可以跑。');
}

export function jobStatusLabel(t: TFn, s: string): { text: string; tone: 'neutral' | 'ok' | 'warn' | 'bad' | 'info' } {
  switch (s) {
    case 'pending':
      return { text: t('排隊中'), tone: 'info' };
    case 'running':
      return { text: t('掃描中'), tone: 'info' };
    case 'succeeded':
      return { text: t('完成'), tone: 'ok' };
    case 'failed':
      return { text: t('失敗'), tone: 'bad' };
    case 'cancelled':
      return { text: t('已取消'), tone: 'neutral' };
    case 'expired':
      return { text: t('沒有掃描端來領'), tone: 'warn' };
    default:
      return { text: s, tone: 'neutral' };
  }
}

export function kindLabel(t: TFn, k: string): string {
  return k === 'verify' ? t('擁有權驗證') : t('掃描');
}

export interface ProofLike {
  verifyMethod: string | null;
  proven: boolean;
  proofExpired: boolean;
}

export function proofLabel(t: TFn, x: ProofLike): { text: string; tone: 'neutral' | 'ok' | 'warn' | 'bad' | 'info'; hint: string } {
  if (x.proven) return { text: t('已驗證'), tone: 'ok', hint: t('已經證明這個網站是你的，可以做主動掃描。') };
  if (x.verifyMethod === 'internal-cidr') return { text: t('內網'), tone: 'info', hint: t('位址在內網網段白名單裡：管理員已聲明是自己的網段，可以做主動掃描。') };
  if (x.proofExpired) return { text: t('驗證已過期'), tone: 'warn', hint: t('擁有權驗證超過 90 天，要重新驗證才能做主動掃描。') };
  return { text: t('未驗證'), tone: 'neutral', hint: t('還沒證明這個網站是你的：只能做被動檢查。') };
}

export function verifyMethodLabel(t: TFn, m: string | null): string {
  switch (m) {
    case 'dns-txt':
      return t('DNS TXT 記錄');
    case 'well-known':
      return t('網站上的驗證檔');
    case 'meta':
      return t('網頁裡的 meta 標籤');
    case 'internal-cidr':
      return t('內網白名單');
    default:
      return '—';
  }
}

/** 位址檢查沒過的原因（繁中原文；經 t() 顯示，測試會檢查每一條都有英文）。 */
export const BLOCK_REASONS: Record<string, string> = {
  unresolvable: '查不到這個網域的位址',
  forbidden_host: '這個名稱不能當掃描目標（本機、雲端 metadata 或 Hub 內部服務）',
  metadata: '位址是雲端主機的 metadata 服務，永遠不准掃',
  self: '位址是 Hub 或掃描端自己',
  loopback: '位址是本機（127.0.0.1／::1）',
  link_local: '位址是 link-local（169.254.x.x／fe80::）',
  multicast: '位址是群播位址',
  reserved: '位址是保留或文件用的網段',
  unspecified: '位址是 0.0.0.0／::',
  invalid_ip: '位址格式不對',
  private_not_allowed: '位址在內網，但不在「允許掃描的內網網段」白名單裡',
};

/** 位址檢查沒過的原因（screen.reason 或 blocked_target:<原因>）。 */
export function blockReasonText(t: TFn, reason: string): string {
  const zh = BLOCK_REASONS[reason];
  return zh ? t(zh) : reason;
}

/** API 錯誤碼的白話（繁中原文；經 t() 顯示，測試會檢查每一條都有英文）。 */
export const ERROR_TEXTS: Record<string, string> = {
  not_verified: '主動掃描前要先證明網站是你的（下面三種方式選一種）。',
  proof_expired: '擁有權驗證已過期，請重新驗證。',
  duplicate: '這個網站已經有同樣的工作在排隊或執行中。',
  no_scanners: '這個層級沒有可用的掃描器（可能都被停用了）。',
  bad_url: '網址格式不對。',
  bad_scheme: '只支援 http:// 與 https://。',
  url_credentials: '網址裡不能放帳號密碼。',
  forbidden_host: '這個名稱不能當掃描目標（本機、雲端 metadata 或 Hub 內部服務）',
  url_too_long: '網址太長。',
  too_many_targets: '目標太多了（上限 500 個）。',
  bad_state: '這個工作已經結束了。',
  cidr_too_broad: '網段太大（IPv4 至少 /8、IPv6 至少 /16）。',
  // 掃描端回報的工作結果（agent/src/webscan）
  runner_stopped: '掃描端被停止，這次掃描沒做完。',
  deadline_exceeded: '超過一次掃描的時間上限（可在設定頁調整）。',
  lease_expired: '掃描端失聯太久，這個工作已放棄。',
  target_deleted: '目標已刪除。',
  all_steps_failed: '每個掃描器都失敗了（請看掃描端的紀錄）。',
  verify_request_failed: '連不上網站，沒辦法檢查驗證檔或 meta 標籤。',
  work_dir_unavailable: '掃描端的暫存目錄不能用。',
  resolver_unavailable: '掃描端沒辦法啟動釘選解析器。',
  cancelled: '已取消。',
};

/** API 錯誤碼 → 白話。 */
export function errorText(t: TFn, code: string | undefined, status: number): string {
  if (!code) return t('失敗（HTTP {n}）', { n: status });
  if (code.startsWith('blocked_target:')) return t('不能掃這個網址：{why}', { why: blockReasonText(t, code.slice('blocked_target:'.length)) });
  if (ERROR_TEXTS[code]) return t(ERROR_TEXTS[code]);
  if (code.startsWith('bad_job:')) return t('掃描端拒絕了這個工作：{why}', { why: code.slice('bad_job:'.length) });
  // 設定頁的 CIDR 錯誤：bad_cidr:<值>、cidr_too_broad:<值>
  if (/^(bad_cidr|cidr_too_broad):/.test(code)) return t('網段格式不對：{v}', { v: code.split(':').slice(1).join(':') });
  return t('失敗：{e}', { e: code });
}

export function durationText(fromIso: string | null, toIso: string | null): string {
  if (!fromIso || !toIso) return '—';
  const s = Math.max(0, Math.round((Date.parse(toIso) - Date.parse(fromIso)) / 1000));
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
