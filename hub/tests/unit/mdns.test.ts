// mDNS 封包編碼／解碼與回覆邏輯（純函式，不開真的 socket）＋ DNS SRV 紀錄推導。
import { describe, expect, it } from 'vitest';
import {
  advertisedPort,
  announcement,
  answerQuery,
  decodePacket,
  encodePacket,
  sanitizeHost,
  serviceConfig,
  SERVICE_TYPE,
  SERVICES_META,
  TYPE,
} from '@/lib/discovery/mdns';
import { srvCommands, srvInfo } from '@/lib/discovery/srv';

const FP = '72AS-YEXT-VNGO-NLC5-W2NM';
const cfg = serviceConfig({
  name: 'Security Hub',
  fingerprint: FP,
  version: '0.2.1',
  publicUrl: 'https://hub.corp.example:8443',
  hostname: 'HUB-01.corp',
  addresses: ['192.168.1.20', '10.0.0.5'],
});

const query = (name: string[], type: number, unicast = false) => decodePacket(encodePacket({ id: 0, flags: 0, questions: [{ name, type, unicast }] }));

describe('service config', () => {
  it('derives instance, host, port and TXT', () => {
    expect(cfg.instance).toEqual(['Security Hub (HUB-01.corp)', ...SERVICE_TYPE]);
    expect(cfg.host).toEqual(['hub-01-corp-asm', 'local']);
    expect(cfg.port).toBe(8443);
    expect(cfg.txt).toEqual([`fp=${FP}`, 'v=0.2.1', 'path=/', 'proto=https', 'url=https://hub.corp.example:8443']);
    expect(advertisedPort('https://h.example')).toBe(443);
    expect(advertisedPort('http://h.example')).toBe(80);
    expect(advertisedPort(null)).toBe(Number(process.env.PORT) || 3000);
    expect(sanitizeHost('---')).toBe('hub');
    const noUrl = serviceConfig({ name: 'X', fingerprint: FP, version: '1', publicUrl: null, hostname: 'a', addresses: [] });
    expect(noUrl.txt).toEqual([`fp=${FP}`, 'v=1', 'path=/', 'proto=http']);
    // 實例名稱最多 63 bytes（不切壞中文字）
    const long = serviceConfig({ name: '資安中樞'.repeat(10), fingerprint: FP, version: '1', publicUrl: null, hostname: 'a', addresses: [] });
    expect(Buffer.byteLength(long.instance[0])).toBeLessThanOrEqual(63);
    expect(long.instance[0]).not.toContain('�');
  });
});

describe('dns packets', () => {
  it('round-trips questions and every record type (names with dots and spaces stay one label)', () => {
    const pkt = encodePacket({
      id: 7,
      flags: 0x8400,
      questions: [{ name: SERVICE_TYPE, type: TYPE.PTR, unicast: true }],
      answers: [
        { name: SERVICE_TYPE, ttl: 4500, flush: false, data: { type: TYPE.PTR, target: ['a.b c', ...SERVICE_TYPE] } },
        { name: ['a.b c', ...SERVICE_TYPE], ttl: 120, flush: true, data: { type: TYPE.SRV, priority: 1, weight: 2, port: 443, target: ['h', 'local'] } },
        { name: ['a.b c', ...SERVICE_TYPE], ttl: 4500, flush: true, data: { type: TYPE.TXT, entries: ['fp=X', 'url=https://h'] } },
        { name: ['h', 'local'], ttl: 120, flush: true, data: { type: TYPE.A, address: '192.0.2.1' } },
      ],
    });
    const d = decodePacket(pkt);
    expect(d.id).toBe(7);
    expect(d.flags).toBe(0x8400);
    expect(d.questions).toEqual([{ name: SERVICE_TYPE, type: TYPE.PTR, unicast: true }]);
    expect(d.answers.map((a) => a.data)).toEqual([
      { type: TYPE.PTR, target: ['a.b c', ...SERVICE_TYPE] },
      { type: TYPE.SRV, priority: 1, weight: 2, port: 443, target: ['h', 'local'] },
      { type: TYPE.TXT, entries: ['fp=X', 'url=https://h'] },
      { type: TYPE.A, address: '192.0.2.1' },
    ]);
    expect(d.answers.map((a) => [a.ttl, a.flush])).toEqual([
      [4500, false],
      [120, true],
      [4500, true],
      [120, true],
    ]);
  });

  it('decodes compressed names and rejects malformed packets', () => {
    // 問題：_ai-security-monitor._tcp.local；答案的名稱用指標 0xc00c 指回問題
    const q = encodePacket({ questions: [{ name: SERVICE_TYPE, type: TYPE.PTR, unicast: false }] });
    const header = Buffer.from(q);
    header.writeUInt16BE(1, 6); // ancount = 1
    const rr = Buffer.concat([Buffer.from([0xc0, 0x0c]), Buffer.from([0, 12, 0, 1, 0, 0, 0, 10, 0, 2]), Buffer.from([0xc0, 0x0c])]);
    const d = decodePacket(Buffer.concat([header, rr]));
    expect(d.answers[0].name).toEqual(SERVICE_TYPE);
    expect(d.answers[0].data).toEqual({ type: TYPE.PTR, target: SERVICE_TYPE });
    expect(() => decodePacket(Buffer.from([0, 0, 0]))).toThrow();
    expect(() => decodePacket(q.subarray(0, q.length - 3))).toThrow();
    // 指標迴圈
    const loop = Buffer.concat([Buffer.from([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]), Buffer.from([0xc0, 0x0c]), Buffer.from([0, 1, 0, 1])]);
    expect(() => decodePacket(loop)).toThrow();
    expect(() => encodePacket({ questions: [{ name: ['x'.repeat(64)], type: 1, unicast: false }] })).toThrow();
  });
});

describe('responder', () => {
  it('answers a PTR browse with SRV/TXT/A in the additionals', () => {
    const r = answerQuery(query(SERVICE_TYPE, TYPE.PTR), cfg)!;
    expect(r.unicast).toBe(false);
    const d = decodePacket(r.packet);
    expect(d.flags & 0x8000).toBe(0x8000);
    expect(d.answers).toHaveLength(1);
    expect(d.answers[0].data).toEqual({ type: TYPE.PTR, target: cfg.instance });
    expect(d.answers[0].ttl).toBe(4500);
    const types = d.additionals.map((a) => a.data.type).sort((a, b) => a - b);
    expect(types).toEqual([TYPE.A, TYPE.A, TYPE.TXT, TYPE.SRV]);
    const srv = d.additionals.find((a) => a.data.type === TYPE.SRV)!;
    expect(srv.data).toMatchObject({ port: 8443, target: cfg.host });
    expect(srv.ttl).toBe(120);
    const txt = d.additionals.find((a) => a.data.type === TYPE.TXT)!;
    expect((txt.data as { entries: string[] }).entries).toContain(`fp=${FP}`);
    expect(d.additionals.filter((a) => a.data.type === TYPE.A).map((a) => (a.data as { address: string }).address)).toEqual(['192.168.1.20', '10.0.0.5']);
  });

  it('honours the QU bit, legacy unicast, service enumeration and direct lookups', () => {
    expect(answerQuery(query(SERVICE_TYPE, TYPE.PTR, true), cfg)!.unicast).toBe(true);
    const meta = decodePacket(answerQuery(query(SERVICES_META, TYPE.PTR), cfg)!.packet);
    expect(meta.answers[0].data).toEqual({ type: TYPE.PTR, target: SERVICE_TYPE });
    const srv = decodePacket(answerQuery(query(cfg.instance.map((l, i) => (i === 0 ? l.toUpperCase() : l)), TYPE.SRV), cfg)!.packet);
    expect(srv.answers[0].data).toMatchObject({ type: TYPE.SRV, port: 8443 });
    const any = decodePacket(answerQuery(query(cfg.instance, TYPE.ANY), cfg)!.packet);
    expect(any.answers.map((a) => a.data.type).sort()).toEqual([TYPE.TXT, TYPE.SRV].sort());
    const a = decodePacket(answerQuery(query(cfg.host, TYPE.A), cfg)!.packet);
    expect(a.answers).toHaveLength(2);
    // 傳統單播（來源 port 不是 5353）：回原 id、附問題、TTL ≤ 10
    const q = decodePacket(encodePacket({ id: 4242, questions: [{ name: SERVICE_TYPE, type: TYPE.PTR, unicast: false }] }));
    const legacy = answerQuery(q, cfg, 54321)!;
    expect(legacy.unicast).toBe(true);
    const ld = decodePacket(legacy.packet);
    expect(ld.id).toBe(4242);
    expect(ld.questions).toHaveLength(1);
    expect(Math.max(...[...ld.answers, ...ld.additionals].map((x) => x.ttl))).toBeLessThanOrEqual(10);
  });

  it('ignores responses, other services and unknown types', () => {
    const resp = decodePacket(encodePacket({ flags: 0x8400, questions: [{ name: SERVICE_TYPE, type: TYPE.PTR, unicast: false }] }));
    expect(answerQuery(resp, cfg)).toBeNull();
    expect(answerQuery(query(['_http', '_tcp', 'local'], TYPE.PTR), cfg)).toBeNull();
    expect(answerQuery(query(cfg.host, TYPE.AAAA), cfg)).toBeNull();
    expect(answerQuery(query(cfg.host, TYPE.A), { ...cfg, addresses: [] })).toBeNull();
  });

  it('announces and says goodbye with TTL 0', () => {
    const hello = decodePacket(announcement(cfg));
    expect(hello.answers.map((a) => a.data.type)).toEqual([TYPE.PTR, TYPE.SRV, TYPE.TXT, TYPE.A, TYPE.A]);
    expect(hello.answers.every((a) => a.ttl > 0)).toBe(true);
    const bye = decodePacket(announcement(cfg, true));
    expect([...bye.answers, ...bye.additionals].every((a) => a.ttl === 0)).toBe(true);
  });
});

describe('DNS SRV record', () => {
  it('derives name, target, port and TXT from the public URL', () => {
    const s = srvInfo('https://hub.corp.acme.com', FP)!;
    expect(s).toEqual({
      name: '_ai-security-monitor._tcp.corp.acme.com',
      domain: 'corp.acme.com',
      target: 'hub.corp.acme.com',
      port: 443,
      txt: ['url=https://hub.corp.acme.com', `fp=${FP}`],
      placeholder: false,
    });
    const cmd = srvCommands(s);
    expect(cmd.windows).toContain('Add-DnsServerResourceRecord -ZoneName corp.acme.com -Name _ai-security-monitor._tcp -Srv -DomainName hub.corp.acme.com -Port 443 -Priority 0 -Weight 0');
    expect(cmd.windows).toContain(`-Txt -DescriptiveText 'fp=${FP}'`);
    expect(cmd.bind).toContain('_ai-security-monitor._tcp.corp.acme.com. 3600 IN SRV 0 0 443 hub.corp.acme.com.');
    expect(cmd.bind).toContain(`_ai-security-monitor._tcp.corp.acme.com. 3600 IN TXT "url=https://hub.corp.acme.com" "fp=${FP}"`);
    const ip = srvInfo('http://192.168.1.5:3000', FP)!;
    expect(ip).toMatchObject({ name: '_ai-security-monitor._tcp.corp.example', target: 'hub.corp.example', port: 3000, placeholder: true });
    expect(srvInfo('http://hub.example:8080', FP)).toMatchObject({ domain: 'corp.example', target: 'hub.example', port: 8080, placeholder: true });
    expect(srvInfo(null, FP)).toBeNull();
  });
});
