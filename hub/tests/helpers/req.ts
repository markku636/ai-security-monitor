// 建 Request 給 route handler 直接呼叫（不需要起伺服器）。
export function req(
  path: string,
  init: { method?: string; body?: unknown; headers?: Record<string, string>; cookie?: string; sameSite?: boolean } = {},
): Request {
  const headers: Record<string, string> = { host: 'localhost:3000', ...(init.headers ?? {}) };
  if (init.body !== undefined) headers['content-type'] = 'application/json';
  if (init.cookie) headers.cookie = init.cookie;
  if (init.sameSite !== false && (init.method ?? 'GET') !== 'GET') {
    headers['x-asa-request'] = '1';
    headers['sec-fetch-site'] = 'same-origin';
  }
  return new Request(`http://localhost:3000${path}`, {
    method: init.method ?? 'GET',
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

/** 從 Set-Cookie 取出 `name=value` 給下一個請求用。 */
export function cookieFrom(res: Response, name: string): string | undefined {
  const sc = res.headers.get('set-cookie') ?? '';
  const m = new RegExp(`${name}=([^;]*)`).exec(sc);
  return m ? `${name}=${m[1]}` : undefined;
}
