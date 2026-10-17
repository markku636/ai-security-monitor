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

/** instrumentation.ts 裝好「TCP 來源位址」標頭時設 true（見 installPeerIpHook）。 */
export const PEER_IP_HEADER = 'x-asa-peer-ip';

const gp = globalThis as unknown as { __asaPeerIpHook?: boolean };

export function peerIpHookInstalled(): boolean {
  return gp.__asaPeerIpHook === true;
}

export function markPeerIpHookInstalled(): void {
  gp.__asaPeerIpHook = true;
}

/** 測試用：模擬 instrumentation 已裝／沒裝 peer IP hook。 */
export function setPeerIpHookForTests(on: boolean): void {
  gp.__asaPeerIpHook = on || undefined;
}

/** `::ffff:a.b.c.d` → `a.b.c.d`；去掉 IPv6 zone（fe80::1%eth0）。 */
export function normalizeIp(ip: string): string {
  let s = ip.trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const pct = s.indexOf('%');
  if (pct > 0) s = s.slice(0, pct);
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  return m ? m[1] : s;
}

/**
 * 真正的連線對端：ASA_HUB_TRUST_PROXY → X-Forwarded-For 最後一個；否則只信 instrumentation 從 socket 填的
 * x-asa-peer-ip（會覆蓋用戶端送來的同名標頭）；都沒有 → null（例如測試或沒跑 instrumentation）。
 * Next.js 只在 X-Forwarded-For 不存在時才補，所以沒開 trust proxy 時絕不能看它。
 */
export function peerIp(req: Request): string | null {
  if (env().trustProxy) {
    const xff = req.headers.get('x-forwarded-for');
    const last = xff?.split(',').pop()?.trim();
    if (last) return normalizeIp(last);
  }
  if (peerIpHookInstalled()) {
    const v = req.headers.get(PEER_IP_HEADER)?.trim();
    if (v) return normalizeIp(v);
  }
  return null;
}

/** 稽核用的來源 IP：peerIp；trust proxy 時才退回 X-Real-IP；都沒有 → 'local'。 */
export function sourceIp(req: Request): string {
  return peerIp(req) ?? (env().trustProxy ? req.headers.get('x-real-ip')?.trim() || null : null) ?? 'local';
}

export function isHttps(req: Request): boolean {
  if (env().trustProxy && req.headers.get('x-forwarded-proto') === 'https') return true;
  return new URL(req.url).protocol === 'https:';
}
