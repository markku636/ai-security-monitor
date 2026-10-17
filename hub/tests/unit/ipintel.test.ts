import { describe, expect, it } from 'vitest';
import { isPublicIp, normalizeIp } from '@/lib/ipintel/ip';
import {
  asnNumber,
  callRdns,
  looksLikeDatacenter,
  parseAbuseipdb,
  parseGreynoise,
  parseIpinfo,
  parseProxycheck,
} from '@/lib/ipintel/providers';
import { riskLevel, scoreIp } from '@/lib/ipintel/score';
import { mergeProfile } from '@/lib/ipintel/service';
import type { LocalHit } from '@/lib/ipintel/types';

const hit = (feedId: string, confidence = 90): LocalHit => ({ feedId, feedName: feedId, vendor: 'v', confidence, sourceUrl: 'https://x' });
const at = new Date().toISOString();

describe('isPublicIp', () => {
  it('rejects private, reserved and documentation ranges', () => {
    for (const ip of ['10.1.2.3', '192.168.50.49', '172.17.48.1', '127.0.0.1', '0.0.0.0', '100.64.0.1', '169.254.1.1', '203.0.113.66', '224.0.0.1', '::1', 'fe80::1', 'fd00::1', '2001:db8::1', 'not-an-ip']) {
      expect(isPublicIp(ip), ip).toBe(false);
    }
  });
  it('accepts public addresses, including IPv4-mapped IPv6', () => {
    for (const ip of ['104.18.9.226', '76.76.21.21', '8.8.8.8', '2606:4700::6810:84e5', '::ffff:1.1.1.1']) {
      expect(isPublicIp(ip), ip).toBe(true);
    }
    expect(normalizeIp('::FFFF:1.1.1.1')).toBe('1.1.1.1');
  });
});

describe('parsers', () => {
  it('AbuseIPDB maps usage type and clamps the score', () => {
    const p = parseAbuseipdb({
      data: { abuseConfidenceScore: 100, totalReports: 42, countryCode: 'CN', usageType: 'Data Center/Web Hosting/Transit', isp: 'X', isTor: false },
    });
    expect(p).toMatchObject({ abuseScore: 100, abuseReports: 42, country: 'CN', usageType: 'datacenter', isDatacenter: true, isTor: false });
    expect(parseAbuseipdb({ data: { abuseConfidenceScore: 0, usageType: 'Fixed Line ISP' } })).toMatchObject({ usageType: 'isp', isDatacenter: false });
    expect(parseAbuseipdb({ errors: [] })).toBeNull();
  });
  it('GreyNoise, ipinfo and proxycheck', () => {
    expect(parseGreynoise({ classification: 'benign', name: 'Cloudflare', riot: true })).toEqual({
      greynoiseClass: 'benign',
      greynoiseName: 'Cloudflare',
      greynoiseRiot: true,
    });
    expect(parseIpinfo({ ip: '1.1.1.1', asn: 'AS13335', as_name: 'Cloudflare, Inc.', country_code: 'AU' })).toMatchObject({
      asn: 13335,
      asnOrg: 'Cloudflare, Inc.',
      country: 'AU',
    });
    expect(
      parseProxycheck({ status: 'ok', '5.6.7.8': { proxy: 'yes', type: 'VPN', risk: 66, isocode: 'NL', asn: 'AS9009', city: 'Amsterdam' } }, '5.6.7.8'),
    ).toMatchObject({ isProxy: true, isVpn: true, proxyRisk: 66, country: 'NL', asn: 9009, city: 'Amsterdam' });
    expect(asnNumber('as16509')).toBe(16509);
    expect(asnNumber('x')).toBeNull();
  });
  it('datacenter keywords use word boundaries for short words', () => {
    expect(looksLikeDatacenter('Amazon.com, Inc.')).toBe(true);
    expect(looksLikeDatacenter('Colombia Movil')).toBe(false);
    expect(looksLikeDatacenter('Acme Colo Services')).toBe(true);
    expect(looksLikeDatacenter(null)).toBeNull();
  });
  it('reverse DNS checks forward confirmation', async () => {
    const ok = await callRdns('1.1.1.1', { reverse: async () => ['one.one.one.one.'], resolve: async () => ['1.1.1.1', '1.0.0.1'] }, 1000);
    expect(ok.data).toEqual({ hostname: 'one.one.one.one', fcrdns: true });
    const bad = await callRdns('9.9.9.9', { reverse: async () => ['evil.example'], resolve: async () => ['1.2.3.4'] }, 1000);
    expect(bad.data?.fcrdns).toBe(false);
    const none = await callRdns('9.9.9.9', { reverse: async () => Promise.reject(Object.assign(new Error('x'), { code: 'ENOTFOUND' })), resolve: async () => [] }, 1000);
    expect(none).toMatchObject({ ok: true, data: { hostname: null, fcrdns: null } });
  });
});

describe('scoreIp', () => {
  it('returns null when nothing was checked', () => {
    expect(scoreIp({}, [], false)).toBeNull();
    expect(scoreIp({}, [], true)).toEqual({ score: 0, level: 'low', reasons: [] });
  });
  it('Spamhaus DROP floors the score at 85', () => {
    const s = scoreIp({}, [hit('spamhaus-drop-v4')], false)!;
    expect(s.score).toBe(85);
    expect(s.level).toBe('critical');
    expect(s.reasons[0]).toMatchObject({ key: 'rule_spamhaus', kind: 'rule' });
    expect(s.reasons.some((r) => r.key === 'spamhaus')).toBe(true);
  });
  it('AbuseIPDB ≥ 90 floors at 75; Tor floors at 40', () => {
    expect(scoreIp({ abuseScore: 95, abuseReports: 10 }, [], true)!.score).toBe(75);
    expect(scoreIp({ isTor: true }, [], true)!.score).toBe(40);
    expect(scoreIp({}, [hit('tor-exits')], false)!.score).toBe(40);
  });
  it('weights add up and GreyNoise benign pulls the score down', () => {
    const bad = scoreIp({ abuseScore: 60, greynoiseClass: 'malicious', isProxy: true, isVpn: true, isDatacenter: true }, [hit('firehol-level1')], true)!;
    // (0.6*25 + 15 + 12 + 8 + 20) / 165 = 70 / 165
    expect(bad.score).toBe(Math.round((100 * 70) / 165));
    expect(bad.level).toBe('medium');
    expect(bad.reasons.map((r) => r.key)).toEqual(['firehol', 'abuseipdb', 'greynoise_malicious', 'proxy', 'datacenter']);
    const cdn = scoreIp({ isDatacenter: true, greynoiseClass: 'benign', greynoiseName: 'Cloudflare' }, [], true)!;
    expect(cdn.score).toBe(0);
    expect(cdn.reasons.find((r) => r.key === 'greynoise_benign')!.contribution).toBeLessThan(0);
  });
  it('levels', () => {
    expect([0, 24, 25, 49, 50, 74, 75, 100].map(riskLevel)).toEqual(['low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical']);
  });
});

describe('mergeProfile', () => {
  it('prefers ipinfo for ASN, AbuseIPDB for usage, and falls back to local GeoIP', () => {
    const p = mergeProfile(
      {
        ipinfo: { ok: true, fetchedAt: at, data: { asn: 13335, asnOrg: 'Cloudflare, Inc.', country: 'US' } },
        abuseipdb: { ok: true, fetchedAt: at, data: { abuseScore: 0, country: 'CA', usageType: 'datacenter', isDatacenter: true } },
        greynoise: { ok: false, reason: 'timeout', fetchedAt: at },
      },
      { country: 'XX', asn: 1 },
    );
    expect(p).toMatchObject({ asn: 13335, country: 'US', usageType: 'datacenter', isDatacenter: true, abuseScore: 0 });
    expect(p.greynoiseClass).toBeUndefined();
    const local = mergeProfile({}, { country: 'CA', asn: 13335, asnOrg: 'Cloudflare, Inc.' });
    expect(local).toMatchObject({ country: 'CA', asn: 13335, isDatacenter: true });
  });
});
