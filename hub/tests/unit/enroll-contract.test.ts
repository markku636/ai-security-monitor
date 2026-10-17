// 契約檔（contract/hub-identity.v1.json、enroll-request.v1.json、enroll-status.v1.json）：
// agent 端也用同一份驗，兩邊的指紋、申請碼、簽章規則才不會走鐘。
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { matchCidr, normalizeCidr, normalizeCidrList } from '@/lib/enroll/cidr';
import {
  approvalMessage,
  base32,
  fingerprintOf,
  FINGERPRINT_RE,
  identityFromPkcs8,
  identityMessage,
  pkcs8FromSeed,
  requestCodeOf,
  sign,
  verifyWithRawKey,
} from '@/lib/enroll/identity';
import { EnrollRequest, deriveClientKey } from '@/lib/enroll/store';
import { normalizeIp } from '@/lib/http';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));
const IDENTITY = load('hub-identity.v1.json');
const REQUEST = load('enroll-request.v1.json');
const STATUS = load('enroll-status.v1.json');
const TEST_KEY = identityFromPkcs8(pkcs8FromSeed(Buffer.alloc(32, 7)));

describe('contract: hub identity', () => {
  it('the test key (seed 0x07×32) matches the published public key and fingerprint', () => {
    expect(TEST_KEY.publicKeyB64).toBe(IDENTITY.public_key);
    expect(fingerprintOf(Buffer.from(IDENTITY.public_key, 'base64url'))).toBe(IDENTITY.fingerprint);
    expect(IDENTITY.fingerprint).toBe('72AS-YEXT-VNGO-NLC5-W2NM');
    expect(IDENTITY.fingerprint).toMatch(FINGERPRINT_RE);
    expect(IDENTITY.algorithm).toBe('ed25519');
  });

  it('the nonce signature verifies and is reproduced byte for byte', () => {
    const msg = identityMessage(IDENTITY.nonce, IDENTITY.fingerprint);
    expect(msg).toBe(`asa-hub-identity|v1|${IDENTITY.nonce}|${IDENTITY.fingerprint}`);
    expect(verifyWithRawKey(IDENTITY.public_key, msg, IDENTITY.signature)).toBe(true);
    expect(sign(TEST_KEY, msg)).toBe(IDENTITY.signature);
    expect(verifyWithRawKey(IDENTITY.public_key, msg + 'x', IDENTITY.signature)).toBe(false);
    expect(verifyWithRawKey('short', msg, IDENTITY.signature)).toBe(false);
  });
});

describe('contract: enroll request / status', () => {
  it('enroll-request.v1.json parses with the hub schema', () => {
    const r = EnrollRequest.safeParse(REQUEST);
    expect(r.success).toBe(true);
    expect(r.data?.agent.id).toBe(STATUS.credentials.agent_id);
    expect(r.data?.hub_fingerprint).toBe(IDENTITY.fingerprint);
    // secret 格式：43..128 個 base64url 字元
    expect(EnrollRequest.safeParse({ ...REQUEST, request_secret: 'a'.repeat(42) }).success).toBe(false);
    expect(EnrollRequest.safeParse({ ...REQUEST, request_secret: 'a'.repeat(129) }).success).toBe(false);
    expect(EnrollRequest.safeParse({ ...REQUEST, request_secret: `${'a'.repeat(42)}=` }).success).toBe(false);
  });

  it('the request code is derived from the secret', () => {
    expect(requestCodeOf(REQUEST.request_secret)).toBe('ENDY-Z24W');
    expect(STATUS.request_code).toBe('ENDY-Z24W');
    expect(requestCodeOf(REQUEST.request_secret + 'x')).not.toBe('ENDY-Z24W');
  });

  it('the approval signature verifies and is reproduced byte for byte', () => {
    const c = STATUS.credentials;
    const msg = approvalMessage(STATUS.request_id, c.agent_id, c.client_key);
    expect(msg).toBe(`asa-enroll-approved|v1|${STATUS.request_id}|${c.agent_id}|${crypto.createHash('sha256').update(c.client_key).digest('hex')}`);
    expect(verifyWithRawKey(IDENTITY.public_key, msg, c.signature)).toBe(true);
    expect(sign(TEST_KEY, msg)).toBe(c.signature);
    expect(c.hub_fingerprint).toBe(IDENTITY.fingerprint);
    expect(c.client_key).toMatch(/^asa_ek_[0-9a-f]{8}_[0-9a-f]{40}$/);
    expect(STATUS.request_id).toMatch(/^rq_[0-9a-f]{24}$/);
    expect(STATUS.poll_interval_s).toBe(15);
  });

  it('derived client keys have the enroll-key shape and depend on every input', () => {
    const k = deriveClientKey('s', 'rq_00112233445566778899aabb', '0a1b2c3d');
    expect(k).toMatch(/^asa_ek_0a1b2c3d_[0-9a-f]{40}$/);
    expect(deriveClientKey('t', 'rq_00112233445566778899aabb', '0a1b2c3d')).not.toBe(k);
    expect(deriveClientKey('s', 'rq_00112233445566778899aabc', '0a1b2c3d')).not.toBe(k);
  });

  it('base32 follows RFC 4648 (no padding)', () => {
    expect(base32(Buffer.from(''))).toBe('');
    expect(base32(Buffer.from('f'))).toBe('MY');
    expect(base32(Buffer.from('fo'))).toBe('MZXQ');
    expect(base32(Buffer.from('foo'))).toBe('MZXW6');
    expect(base32(Buffer.from('foob'))).toBe('MZXW6YQ');
    expect(base32(Buffer.from('fooba'))).toBe('MZXW6YTB');
    expect(base32(Buffer.from('foobar'))).toBe('MZXW6YTBOI');
  });
});

describe('CIDR helpers', () => {
  it('normalizes and matches IPv4 / IPv6', () => {
    expect(normalizeCidr('192.168.1.77/24')).toBe('192.168.1.0/24');
    expect(normalizeCidr('10.1.2.3')).toBe('10.1.2.3/32');
    expect(normalizeCidr('2001:DB8::1/48')).toBe('2001:db8::/48');
    expect(normalizeCidr('fe80::1')).toBe('fe80::1/128');
    expect(normalizeCidr('::ffff:10.0.0.1')).toBe('10.0.0.1/32');
    expect(normalizeCidr('10.0.0.0/7')).toEqual({ error: 'cidr_too_broad', value: '10.0.0.0/7' });
    expect(normalizeCidr('1.2.3.4/-1')).toEqual({ error: 'bad_cidr', value: '1.2.3.4/-1' });
    expect(normalizeCidrList(['10.0.0.0/8', '10.0.0.0/8', ''])).toEqual(['10.0.0.0/8']);
    expect(normalizeCidrList('10.0.0.0/8')).toMatchObject({ error: 'bad_cidr' });
    expect(matchCidr('10.9.8.7', ['192.168.0.0/16', '10.0.0.0/8'])).toBe('10.0.0.0/8');
    expect(matchCidr('::ffff:192.168.3.4', ['192.168.0.0/16'])).toBe('192.168.0.0/16');
    expect(matchCidr('2001:db8:0:1::5', ['2001:db8::/48'])).toBe('2001:db8::/48');
    expect(matchCidr('2001:db9::5', ['2001:db8::/48'])).toBeNull();
    expect(matchCidr('172.16.0.1', ['10.0.0.0/8'])).toBeNull();
    expect(matchCidr(null, ['10.0.0.0/8'])).toBeNull();
    expect(matchCidr('local', ['10.0.0.0/8'])).toBeNull();
    expect(normalizeIp('[::1]')).toBe('::1');
    expect(normalizeIp('fe80::1%eth0')).toBe('fe80::1');
  });
});
