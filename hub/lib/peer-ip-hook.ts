// TCP 來源位址標頭：Next.js 只在 X-Forwarded-For 不存在時才補（用戶端可以偽造），
// 所以在 http(s).Server 的 'request' 事件最前面，把 socket 的對端位址寫進 x-asa-peer-ip（覆蓋用戶端送來的同名標頭）。
// 只給 lib/http.ts 的 peerIp() 用（自動核准網段）；由 instrumentation.ts 在 Node runtime 安裝一次。
import http from 'node:http';
import https from 'node:https';
import type { IncomingMessage } from 'node:http';
import { markPeerIpHookInstalled, PEER_IP_HEADER } from '@/lib/http';

const g = globalThis as unknown as { __asaPeerIpPatched?: boolean };

function patch(proto: { emit: (event: string | symbol, ...args: unknown[]) => boolean }): void {
  const orig = proto.emit;
  proto.emit = function (this: unknown, event: string | symbol, ...args: unknown[]): boolean {
    if (event === 'request') {
      const req = args[0] as IncomingMessage | undefined;
      if (req?.headers) {
        const addr = req.socket?.remoteAddress ?? '';
        req.headers[PEER_IP_HEADER] = addr;
        // rawHeaders 也一併改（用戶端自己送的同名標頭拿掉），不管框架從哪個讀都一樣
        if (Array.isArray(req.rawHeaders)) {
          const raw: string[] = [];
          for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
            if (req.rawHeaders[i].toLowerCase() !== PEER_IP_HEADER) raw.push(req.rawHeaders[i], req.rawHeaders[i + 1]);
          }
          raw.push(PEER_IP_HEADER, addr);
          req.rawHeaders = raw;
        }
      }
    }
    return orig.call(this, event, ...args);
  };
}

export function installPeerIpHook(): void {
  if (g.__asaPeerIpPatched) return;
  patch(http.Server.prototype as unknown as Parameters<typeof patch>[0]);
  patch(https.Server.prototype as unknown as Parameters<typeof patch>[0]);
  g.__asaPeerIpPatched = true;
  markPeerIpHookInstalled();
}
