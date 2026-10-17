// 安全分數的白話說明（總覽與主機頁共用）。依 agent/src/scan/score.rs 的實際算法寫；改公式時要一起改。
import type { TFn } from '@/lib/i18n/core';

export type ScoreKey = 'overall' | 'connections' | 'exposure' | 'vulns' | 'hardening';

export const SCORE_KEYS: ScoreKey[] = ['overall', 'connections', 'exposure', 'vulns', 'hardening'];

export function scoreLabels(t: TFn): Record<ScoreKey, string> {
  return {
    overall: t('總分'),
    connections: t('連線'),
    exposure: t('對外曝露'),
    vulns: t('漏洞'),
    hardening: t('安全設定'),
  };
}

export function scoreHints(t: TFn): Record<ScoreKey | 'card', string> {
  return {
    card: t('0–100 分，越高越安全：90 以上綠色、70–89 黃綠、50–69 橘色、50 以下紅色。每找到一個問題就依嚴重度扣分。'),
    overall: t('四項分數的加權平均：連線 30%、對外曝露 20%、漏洞 25%、安全設定 25%；沒有掃描到的項目不計入。'),
    connections: t('這台電腦連到的地方安不安全：連到威脅情資列名的位址、或行為異常（例如定時連回同一個地方）就扣分。每個問題依嚴重度扣分：嚴重 25、高 15、中 7、低 2。'),
    exposure: t('有多少服務（port）能從網路被別人連進來，例如遠端桌面、檔案分享、資料庫。開得越多、越危險，分數越低。'),
    vulns: t('作業系統與軟體有沒有已知漏洞、是否已經停止支援、多久沒更新；已被證實遭駭客利用的漏洞（CISA KEV）多扣 10 分。'),
    hardening: t('系統安全設定檢查的通過率，例如防毒、防火牆、磁碟加密、UAC、SSH 設定；越重要的檢查佔比越高。'),
  };
}
