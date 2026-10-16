// 記憶體內的簡單限流（單一 hub 行程；多實例部署由 writer lock 保證只有一個 hub 在跑）。
const g = globalThis as unknown as { __asaRate?: Map<string, number[]> };

function buckets(): Map<string, number[]> {
  if (!g.__asaRate) g.__asaRate = new Map();
  return g.__asaRate;
}

/** 記一次失敗；回傳目前時間窗內的次數。 */
export function hit(key: string, windowMs: number): number {
  const now = Date.now();
  const list = (buckets().get(key) ?? []).filter((t) => now - t < windowMs);
  list.push(now);
  buckets().set(key, list);
  return list.length;
}

export function count(key: string, windowMs: number): number {
  const now = Date.now();
  return (buckets().get(key) ?? []).filter((t) => now - t < windowMs).length;
}

export function clear(key: string): void {
  buckets().delete(key);
}

export function resetRateLimitsForTests(): void {
  g.__asaRate = new Map();
}
