// 網站掃描的共用常數（不含 node 模組：頁面元件與 server 端共用，避免像 SCOPES／EVENTS 那樣各複製一份）。
//
// 掃描層級：
//   passive       已登錄就能跑（還沒驗證擁有權也可以）：只做跟一般瀏覽器差不多的幾個請求
//   active_light  已驗證擁有權、或位址在管理員設定的內網網段白名單內：會送出探測請求，但不做注入、DoS、模糊測試
// 授權：GPL 不等於不能商用（以未修改的獨立程式執行、映像附授權全文）；只有條款真的限制商用的工具才標 commercialOk=false。

export const WEBSCAN_PROFILES = ['passive', 'active_light'] as const;
export type WebscanProfile = (typeof WEBSCAN_PROFILES)[number];

export const WEBSCAN_SCANNERS = ['httpx', 'tlsx', 'nuclei', 'testssl'] as const;
export type WebscanScanner = (typeof WEBSCAN_SCANNERS)[number];

export const WEBSCAN_JOB_STATUSES = ['pending', 'running', 'succeeded', 'failed', 'cancelled', 'expired'] as const;
export type WebscanJobStatus = (typeof WEBSCAN_JOB_STATUSES)[number];
export const WEBSCAN_OPEN_STATUSES: WebscanJobStatus[] = ['pending', 'running'];

export const WEBSCAN_VERIFY_METHODS = ['dns-txt', 'well-known', 'meta'] as const;
export type WebscanVerifyMethod = (typeof WEBSCAN_VERIFY_METHODS)[number];

export const WEB_FINDING_STATUSES = ['open', 'acked', 'suppressed', 'resolved'] as const;
export type WebFindingStatus = (typeof WEB_FINDING_STATUSES)[number];

export interface ScannerInfo {
  /** 最低要哪個層級才會跑。 */
  tierMin: WebscanProfile;
  license: string;
  commercialOk: boolean;
  /** 原始輸出格式（上傳的 artifact）。 */
  format: 'jsonl' | 'json';
  /** 會不會把目標資訊送給第三方（例如被動子網域來源）；true 的預設關、要在設定頁打開。 */
  thirdParty: boolean;
  homepage: string;
}

export const SCANNER_INFO: Record<WebscanScanner, ScannerInfo> = {
  httpx: { tierMin: 'passive', license: 'MIT', commercialOk: true, format: 'jsonl', thirdParty: false, homepage: 'https://github.com/projectdiscovery/httpx' },
  tlsx: { tierMin: 'passive', license: 'MIT', commercialOk: true, format: 'jsonl', thirdParty: false, homepage: 'https://github.com/projectdiscovery/tlsx' },
  nuclei: { tierMin: 'active_light', license: 'MIT', commercialOk: true, format: 'jsonl', thirdParty: false, homepage: 'https://github.com/projectdiscovery/nuclei' },
  testssl: { tierMin: 'active_light', license: 'GPL-2.0-only', commercialOk: true, format: 'json', thirdParty: false, homepage: 'https://github.com/testssl/testssl.sh' },
};

const RANK: Record<WebscanProfile, number> = { passive: 0, active_light: 1 };

/** 這個層級會跑哪些掃描器（依登錄表的最低層級）。 */
export function scannersFor(profile: WebscanProfile): WebscanScanner[] {
  return WEBSCAN_SCANNERS.filter((s) => RANK[SCANNER_INFO[s].tierMin] <= RANK[profile]);
}

export function isProfile(v: unknown): v is WebscanProfile {
  return typeof v === 'string' && (WEBSCAN_PROFILES as readonly string[]).includes(v);
}

export function isScanner(v: unknown): v is WebscanScanner {
  return typeof v === 'string' && (WEBSCAN_SCANNERS as readonly string[]).includes(v);
}

/** 擁有權驗證的有效天數：過期後要重新驗證才能做主動掃描。 */
export const VERIFY_TTL_DAYS = 90;
