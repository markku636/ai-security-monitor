// 查詢字串小工具：頁面（searchParams 物件）與 API（URLSearchParams）共用同一套解析。

export type Params = URLSearchParams | Record<string, string | string[] | undefined>;

export function getParam(p: Params, k: string): string | undefined {
  if (p instanceof URLSearchParams) return p.get(k) ?? undefined;
  const v = p[k];
  return Array.isArray(v) ? v[0] : v;
}

export function strParam(p: Params, k: string, max: number): string | undefined {
  const v = getParam(p, k)?.trim();
  return v ? v.slice(0, max) : undefined;
}

/** 逗號分隔清單，只留允許的值。 */
export function listParam<T extends string>(p: Params, k: string, allowed: readonly T[]): T[] {
  return (getParam(p, k) ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s): s is T => (allowed as readonly string[]).includes(s));
}

export function clampInt(p: Params, k: string, def: number, min: number, max: number): number {
  const raw = getParam(p, k);
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.floor(n), min), max);
}

/** 篩選條件 → 查詢字串（頁面上的連結與分頁用）。 */
export function toQuery(obj: Record<string, string | number | string[] | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      if (v.length) sp.set(k, v.join(','));
    } else {
      sp.set(k, String(v));
    }
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}
