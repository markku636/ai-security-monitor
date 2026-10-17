// 最小的 DNS 封包編碼／解碼（mDNS 用；名稱以 label 陣列表示，實例名稱裡可以有空白、點、括號）。
export const TYPE = { A: 1, PTR: 12, TXT: 16, AAAA: 28, SRV: 33, ANY: 255 } as const;
const CLASS_IN = 1;

export type Labels = string[];

export interface Question {
  name: Labels;
  type: number;
  /** QU：要求單播回覆。 */
  unicast: boolean;
}

export type RData =
  | { type: typeof TYPE.A; address: string }
  | { type: typeof TYPE.PTR; target: Labels }
  | { type: typeof TYPE.SRV; priority: number; weight: number; port: number; target: Labels }
  | { type: typeof TYPE.TXT; entries: string[] }
  | { type: number; raw: Buffer };

export interface Record_ {
  name: Labels;
  ttl: number;
  /** unique record 的 cache-flush 位元。 */
  flush: boolean;
  data: RData;
}

export interface Packet {
  id: number;
  flags: number;
  questions: Question[];
  answers: Record_[];
  authorities: Record_[];
  additionals: Record_[];
}

// ---- 編碼 ----

function encodeName(labels: Labels): Buffer {
  const parts: Buffer[] = [];
  for (const l of labels) {
    const b = Buffer.from(l, 'utf8');
    if (b.length === 0 || b.length > 63) throw new Error(`bad dns label length: ${b.length}`);
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff);
  return b;
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
}

function encodeRData(d: RData): Buffer {
  if (d.type === TYPE.A && 'address' in d) return Buffer.from(d.address.split('.').map(Number));
  if (d.type === TYPE.PTR && 'target' in d && !('port' in d)) return encodeName(d.target);
  if (d.type === TYPE.SRV && 'port' in d) return Buffer.concat([u16(d.priority), u16(d.weight), u16(d.port), encodeName(d.target)]);
  if (d.type === TYPE.TXT && 'entries' in d) {
    const parts = d.entries.length ? d.entries : [''];
    return Buffer.concat(
      parts.map((e) => {
        const b = Buffer.from(e, 'utf8').subarray(0, 255);
        return Buffer.concat([Buffer.from([b.length]), b]);
      }),
    );
  }
  if ('raw' in d) return d.raw;
  throw new Error('unsupported rdata');
}

function encodeRecord(r: Record_): Buffer {
  const rdata = encodeRData(r.data);
  return Buffer.concat([encodeName(r.name), u16(r.data.type), u16(CLASS_IN | (r.flush ? 0x8000 : 0)), u32(r.ttl), u16(rdata.length), rdata]);
}

export function encodePacket(p: Partial<Packet>): Buffer {
  const q = p.questions ?? [];
  const an = p.answers ?? [];
  const ns = p.authorities ?? [];
  const ar = p.additionals ?? [];
  return Buffer.concat([
    u16(p.id ?? 0),
    u16(p.flags ?? 0),
    u16(q.length),
    u16(an.length),
    u16(ns.length),
    u16(ar.length),
    ...q.map((x) => Buffer.concat([encodeName(x.name), u16(x.type), u16(CLASS_IN | (x.unicast ? 0x8000 : 0))])),
    ...an.map(encodeRecord),
    ...ns.map(encodeRecord),
    ...ar.map(encodeRecord),
  ]);
}

// ---- 解碼（支援名稱壓縮指標；任何越界都丟錯，呼叫端忽略該封包） ----

class Reader {
  constructor(
    readonly buf: Buffer,
    public off = 0,
  ) {}
  need(n: number) {
    if (this.off + n > this.buf.length) throw new Error('truncated dns packet');
  }
  u8() {
    this.need(1);
    return this.buf[this.off++];
  }
  u16() {
    this.need(2);
    const v = this.buf.readUInt16BE(this.off);
    this.off += 2;
    return v;
  }
  u32() {
    this.need(4);
    const v = this.buf.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }
  bytes(n: number) {
    this.need(n);
    const b = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return b;
  }
  name(): Labels {
    const labels: Labels = [];
    let off = this.off;
    let jumped = false;
    let hops = 0;
    for (;;) {
      if (off >= this.buf.length) throw new Error('truncated dns name');
      const len = this.buf[off];
      if (len === 0) {
        off += 1;
        break;
      }
      if ((len & 0xc0) === 0xc0) {
        if (off + 1 >= this.buf.length) throw new Error('truncated dns pointer');
        if (++hops > 32) throw new Error('dns pointer loop');
        const ptr = ((len & 0x3f) << 8) | this.buf[off + 1];
        if (!jumped) this.off = off + 2;
        jumped = true;
        off = ptr;
        continue;
      }
      if (len > 63) throw new Error('bad dns label');
      if (off + 1 + len > this.buf.length) throw new Error('truncated dns label');
      labels.push(this.buf.subarray(off + 1, off + 1 + len).toString('utf8'));
      if (labels.length > 128) throw new Error('dns name too long');
      off += 1 + len;
    }
    if (!jumped) this.off = off;
    return labels;
  }
}

function decodeRecord(r: Reader): Record_ {
  const name = r.name();
  const type = r.u16();
  const cls = r.u16();
  const ttl = r.u32();
  const len = r.u16();
  const start = r.off;
  r.need(len);
  let data: RData;
  if (type === TYPE.A && len === 4) data = { type, address: Array.from(r.bytes(4)).join('.') };
  else if (type === TYPE.PTR) data = { type, target: r.name() };
  else if (type === TYPE.SRV) {
    const priority = r.u16();
    const weight = r.u16();
    const port = r.u16();
    data = { type, priority, weight, port, target: r.name() };
  } else if (type === TYPE.TXT) {
    const entries: string[] = [];
    while (r.off < start + len) {
      const n = r.u8();
      entries.push(r.bytes(n).toString('utf8'));
    }
    data = { type, entries };
  } else data = { type, raw: Buffer.from(r.bytes(len)) };
  r.off = start + len;
  return { name, ttl, flush: (cls & 0x8000) !== 0, data };
}

export function decodePacket(buf: Buffer): Packet {
  const r = new Reader(buf);
  const id = r.u16();
  const flags = r.u16();
  const qd = r.u16();
  const an = r.u16();
  const ns = r.u16();
  const ar = r.u16();
  if (qd > 64 || an + ns + ar > 256) throw new Error('dns packet too large');
  const questions: Question[] = [];
  for (let i = 0; i < qd; i++) {
    const name = r.name();
    const type = r.u16();
    const cls = r.u16();
    questions.push({ name, type, unicast: (cls & 0x8000) !== 0 });
  }
  const rec = (n: number) => Array.from({ length: n }, () => decodeRecord(r));
  return { id, flags, questions, answers: rec(an), authorities: rec(ns), additionals: rec(ar) };
}
