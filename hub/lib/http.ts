// HTTP 小工具：JSON 回應、錯誤、讀 body（有上限）、cookie、來源 IP。
import { env } from '@/lib/env';

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
}

export function error(status: number, code: string, extra: Record<string, unknown> = {}): Response {
  return json({ error: code, ...extra }, status);
}

export class BodyTooLarge extends Error {}

/** 把 body 讀成 bytes；以實際讀到的位元組數判斷上限（不信任 Content-Length）。 */
export async function readBytes(req: Request, maxBytes: number): Promise<Buffer> {
  const declared = Number(req.headers.get('content-length') ?? '0');
  if (declared > maxBytes) throw new BodyTooLarge();
  const reader = req.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new BodyTooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

export async function readJson<T = unknown>(req: Request, maxBytes: number): Promise<T> {
  const text = new TextDecoder().decode(await readBytes(req, maxBytes));
  return (text ? JSON.parse(text) : {}) as T;
}

export function parseCookies(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.get('cookie') ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    try {
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    } catch {
      // 壞掉的 cookie 值直接略過
    }
  }
  return out;
}

/** 來源 IP：只有 ASA_HUB_TRUST_PROXY 時才看 X-Forwarded-For（取最後一個）。 */
export function sourceIp(req: Request): string {
  if (env().trustProxy) {
    const xff = req.headers.get('x-forwarded-for');
    if (xff) return xff.split(',').pop()!.trim();
  }
  return req.headers.get('x-real-ip') ?? 'local';
}

export function isHttps(req: Request): boolean {
  if (env().trustProxy && req.headers.get('x-forwarded-proto') === 'https') return true;
  return new URL(req.url).protocol === 'https:';
}
