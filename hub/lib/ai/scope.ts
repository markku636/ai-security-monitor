// AI 分析範圍的共用常數（server／client 都會 import，不能依賴 node 模組）。

/** 「請 AI 分析選取的 IP」一次最多幾個 IP。 */
export const AI_MAX_IPS = 20;

/** 逗號／空白分隔的 IP 清單 → 去重後的陣列（格式由 server 端用 isIP 驗證）。 */
export function splitIpList(s: string | null | undefined): string[] {
  return [...new Set((s ?? '').split(/[\s,，、]+/).map((x) => x.trim()).filter(Boolean))];
}
