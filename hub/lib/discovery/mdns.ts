// 區網自動尋找（mDNS／DNS-SD）：Hub 在區網廣播 `_ai-security-monitor._tcp.local`，電腦端不用輸入網址就找得到。
// 只用 node:dgram 實作最小的 responder（IPv4、UDP 5353、群組 224.0.0.251）：
//   PTR _ai-security-monitor._tcp.local、_services._dns-sd._udp.local；實例的 SRV／TXT；主機的 A。
// 任何錯誤（port 被占用等）只記一次 log、反映在狀態，不讓 Hub 掛掉。
// 注意：Docker Desktop／bridge 網路不會把 multicast 轉到區網（Linux 用 network_mode: host，
// 或在區網的一台電腦上跑 `ai-security-monitor hub advertise --url <對外網址>`）。
import dgram from 'node:dgram';
import os from 'node:os';
import { env, readEnv } from '@/lib/env';
import { safeHubUrl } from '@/lib/install';
import { decodePacket, encodePacket, TYPE, type Labels, type Packet, type Question, type Record_ } from './dns';

export { decodePacket, encodePacket, TYPE } from './dns';

export const SERVICE_TYPE = ['_ai-security-monitor', '_tcp', 'local'];
export const SERVICES_META = ['_services', '_dns-sd', '_udp', 'local'];
export const MDNS_ADDR = '224.0.0.251';
export const MDNS_PORT = 5353;

const TTL_HOST = 120;
const TTL_SHARED = 4500;

// ---- 服務設定 ----

export function nameEq(a: Labels, b: Labels): boolean {
  return a.length === b.length && a.every((l, i) => l.toLowerCase() === b[i].toLowerCase());
}

export function sanitizeHost(h: string): string {
  const s = h
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 50);
  return s || 'hub';
}

/** UTF-8 不超過 63 bytes（不切斷多位元組字元）。 */
function clipLabel(s: string): string {
  let out = '';
  for (const ch of s.replace(/[\u0000-\u001f\u007f]/g, '')) {
    if (Buffer.byteLength(out + ch, 'utf8') > 63) break;
    out += ch;
  }
  return out || 'Security Hub';
}

export interface ServiceConfig {
  instance: Labels;
  host: Labels;
  port: number;
  txt: string[];
  addresses: string[];
}

export function lanIPv4s(): string[] {
  const out: string[] = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list ?? []) {
      if (a.family === 'IPv4' && !a.internal) out.push(a.address);
    }
  }
  return [...new Set(out)];
}

/** 對外網址的 port：明寫的 port，否則依 scheme 443／80；沒設對外網址 → PORT 或 3000。 */
export function advertisedPort(publicUrl: string | null): number {
  if (publicUrl) {
    const u = new URL(publicUrl);
    if (u.port) return Number(u.port);
    return u.protocol === 'https:' ? 443 : 80;
  }
  const p = Number(process.env.PORT);
  return Number.isInteger(p) && p > 0 && p < 65536 ? p : 3000;
}

export function serviceConfig(o: { name: string; fingerprint: string; version: string; publicUrl: string | null; hostname?: string; addresses?: string[] }): ServiceConfig {
  const hostname = o.hostname ?? os.hostname();
  const url = o.publicUrl ? new URL(o.publicUrl) : null;
  const txt = [
    `fp=${o.fingerprint}`,
    `v=${o.version}`,
    `path=${url && url.pathname && url.pathname !== '' ? url.pathname : '/'}`,
    `proto=${url?.protocol === 'https:' ? 'https' : 'http'}`,
    ...(o.publicUrl ? [`url=${o.publicUrl}`] : []),
  ];
  return {
    instance: [clipLabel(`${o.name} (${hostname})`), ...SERVICE_TYPE],
    host: [`${sanitizeHost(hostname)}-asm`, 'local'],
    port: advertisedPort(o.publicUrl),
    txt,
    addresses: o.addresses ?? lanIPv4s(),
  };
}

function records(cfg: ServiceConfig, ttlScale = 1) {
  const t = (n: number) => n * ttlScale;
  return {
    meta: { name: SERVICES_META, ttl: t(TTL_SHARED), flush: false, data: { type: TYPE.PTR, target: SERVICE_TYPE } } as Record_,
    ptr: { name: SERVICE_TYPE, ttl: t(TTL_SHARED), flush: false, data: { type: TYPE.PTR, target: cfg.instance } } as Record_,
    srv: { name: cfg.instance, ttl: t(TTL_HOST), flush: true, data: { type: TYPE.SRV, priority: 0, weight: 0, port: cfg.port, target: cfg.host } } as Record_,
    txt: { name: cfg.instance, ttl: t(TTL_SHARED), flush: true, data: { type: TYPE.TXT, entries: cfg.txt } } as Record_,
    a: cfg.addresses.map((address) => ({ name: cfg.host, ttl: t(TTL_HOST), flush: true, data: { type: TYPE.A, address } }) as Record_),
  };
}

export interface Reply {
  packet: Buffer;
  /** true → 單播回給發問者；false → 送到群組。 */
  unicast: boolean;
  /** 傳統單播查詢（來源 port 不是 5353）：要原樣回 id 與問題。 */
  legacy: boolean;
}

/** 對一個查詢封包算出回覆（純函式，測試直接呼叫）；跟我們無關 → null。 */
export function answerQuery(query: Packet, cfg: ServiceConfig, srcPort = MDNS_PORT): Reply | null {
  if (query.flags & 0x8000) return null; // 是回應，不是查詢
  const rec = records(cfg);
  const answers: Record_[] = [];
  const additionals: Record_[] = [];
  const add = (list: Record_[], r: Record_) => {
    if (!list.includes(r)) list.push(r);
  };
  const is = (q: Question, t: number) => q.type === t || q.type === TYPE.ANY;
  let unicast = false;
  for (const q of query.questions) {
    let hit = false;
    if (nameEq(q.name, SERVICES_META) && is(q, TYPE.PTR)) {
      add(answers, rec.meta);
      hit = true;
    }
    if (nameEq(q.name, SERVICE_TYPE) && is(q, TYPE.PTR)) {
      add(answers, rec.ptr);
      add(additionals, rec.srv);
      add(additionals, rec.txt);
      rec.a.forEach((a) => add(additionals, a));
      hit = true;
    }
    if (nameEq(q.name, cfg.instance)) {
      if (is(q, TYPE.SRV)) {
        add(answers, rec.srv);
        rec.a.forEach((a) => add(additionals, a));
        hit = true;
      }
      if (is(q, TYPE.TXT)) {
        add(answers, rec.txt);
        hit = true;
      }
    }
    if (nameEq(q.name, cfg.host) && is(q, TYPE.A) && rec.a.length) {
      rec.a.forEach((a) => add(answers, a));
      hit = true;
    }
    if (hit && q.unicast) unicast = true;
  }
  if (!answers.length) return null;
  const legacy = srcPort !== MDNS_PORT;
  const extra = additionals.filter((r) => !answers.includes(r));
  // 傳統單播：回原 id、附上問題，TTL 不超過 10 秒（RFC 6762 §6.7）
  const scale = (list: Record_[]) => (legacy ? list.map((r) => ({ ...r, ttl: Math.min(r.ttl, 10), flush: false })) : list);
  return {
    packet: encodePacket({
      id: legacy ? query.id : 0,
      flags: 0x8400,
      questions: legacy ? query.questions.map((q) => ({ ...q, unicast: false })) : [],
      answers: scale(answers),
      additionals: scale(extra),
    }),
    unicast: unicast || legacy,
    legacy,
  };
}

/** 主動宣告（啟動時）或 goodbye（ttl 0，關閉時）。 */
export function announcement(cfg: ServiceConfig, goodbye = false): Buffer {
  const rec = records(cfg, goodbye ? 0 : 1);
  return encodePacket({ id: 0, flags: 0x8400, answers: [rec.ptr, rec.srv, rec.txt, ...rec.a], additionals: [rec.meta] });
}

// ---- 執行中的 responder ----

export interface MdnsStatus {
  enabled: boolean;
  running: boolean;
  port: number | null;
  error?: string;
}

const g = globalThis as unknown as {
  __asaMdns?: { socket: dgram.Socket | null; cfg: ServiceConfig | null; status: MdnsStatus };
};

function state() {
  if (!g.__asaMdns) g.__asaMdns = { socket: null, cfg: null, status: { enabled: mdnsEnabled(), running: false, port: null } };
  return g.__asaMdns;
}

/** ASA_HUB_MDNS：明寫就照寫的；沒寫 → 伺服器版開、單機版關。 */
export function mdnsEnabled(): boolean {
  const v = readEnv('ASA_HUB_MDNS').toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'off'].includes(v)) return false;
  return env().edition === 'server';
}

export function mdnsStatus(): MdnsStatus {
  const s = state().status;
  return { ...s, enabled: mdnsEnabled() };
}

/** 啟動 responder（重複呼叫無害）。`identity` 由呼叫端給（需要資料庫）。 */
export function startMdns(o: { name: string; fingerprint: string; version: string }): void {
  const st = state();
  if (st.socket || !mdnsEnabled()) return;
  const publicUrl = safeHubUrl(readEnv('ASA_HUB_PUBLIC_URL') || undefined);
  let cfg: ServiceConfig;
  try {
    cfg = serviceConfig({ ...o, publicUrl });
  } catch (e) {
    st.status = { enabled: true, running: false, port: null, error: e instanceof Error ? e.message : String(e) };
    return;
  }
  st.cfg = cfg;
  st.status = { enabled: true, running: false, port: cfg.port };
  let logged = false;
  const fail = (e: unknown) => {
    const msg = e instanceof Error ? e.message : String(e);
    st.status = { enabled: true, running: false, port: cfg.port, error: msg };
    if (!logged) console.warn(`[ai-security-monitor-hub] mDNS advertising unavailable: ${msg}`);
    logged = true;
    try {
      st.socket?.close();
    } catch {
      // 已關
    }
    st.socket = null;
  };
  let sock: dgram.Socket;
  try {
    sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  } catch (e) {
    fail(e);
    return;
  }
  st.socket = sock;
  sock.on('error', fail);
  sock.on('message', (msg, rinfo) => {
    let q: Packet;
    try {
      q = decodePacket(msg);
    } catch {
      return;
    }
    // 每次回覆都用最新的網卡位址（DHCP 換 IP 也跟得上）
    const reply = answerQuery(q, { ...cfg, addresses: lanIPv4s() }, rinfo.port);
    if (!reply) return;
    const [port, addr] = reply.unicast ? [rinfo.port, rinfo.address] : [MDNS_PORT, MDNS_ADDR];
    sock.send(reply.packet, port, addr, () => undefined);
  });
  try {
    sock.bind(MDNS_PORT, () => {
      try {
        sock.addMembership(MDNS_ADDR);
        sock.setMulticastTTL(255);
        sock.setMulticastLoopback(true);
      } catch (e) {
        fail(e);
        return;
      }
      st.status = { enabled: true, running: true, port: cfg.port };
      console.log(`[ai-security-monitor-hub] mDNS: advertising ${cfg.instance[0]} on port ${cfg.port}`);
      const announce = () => {
        if (st.socket !== sock) return;
        sock.send(announcement({ ...cfg, addresses: lanIPv4s() }), MDNS_PORT, MDNS_ADDR, () => undefined);
      };
      announce();
      setTimeout(announce, 1000).unref();
    });
  } catch (e) {
    fail(e);
    return;
  }
  sock.unref();
  // 掛了 signal listener 會取消 Node 預設的「收到就結束」：沒有別人處理時自己結束。
  const bye = (sig: NodeJS.Signals) => {
    stopMdns();
    if (process.listenerCount(sig) === 0) setTimeout(() => process.exit(0), 200);
  };
  process.once('SIGTERM', bye);
  process.once('SIGINT', bye);
}

/** 送 goodbye（盡力而為）後關閉。 */
export function stopMdns(): void {
  const st = state();
  const sock = st.socket;
  if (!sock) return;
  st.socket = null;
  st.status = { ...st.status, running: false };
  try {
    if (st.cfg) sock.send(announcement({ ...st.cfg, addresses: lanIPv4s() }, true), MDNS_PORT, MDNS_ADDR, () => sock.close());
    else sock.close();
  } catch {
    // 關閉途中出錯就算了
  }
}
