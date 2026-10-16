'use client';

/** 瀏覽器端呼叫自家 API：一律帶 X-ASA-Request（CSRF 防護的一半）。 */
export async function apiPost<T = unknown>(path: string, body: unknown): Promise<{ ok: boolean; status: number; data: T }> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-asa-request': '1' },
    body: JSON.stringify(body),
    credentials: 'same-origin',
  });
  let data: T;
  try {
    data = (await res.json()) as T;
  } catch {
    data = {} as T;
  }
  return { ok: res.ok, status: res.status, data };
}
