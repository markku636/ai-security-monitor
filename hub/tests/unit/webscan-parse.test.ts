import { describe, expect, it } from 'vitest';
import { BLOCK_REASONS, ERROR_TEXTS } from '@/components/webscan/labels';
import { en } from '@/messages/en';
import { HTTPX_TITLES, parseHttpx } from '@/lib/webscan/parse/httpx';
import { maskSecret, parseNuclei } from '@/lib/webscan/parse/nuclei';
import { parseTestssl, TESTSSL_TITLES } from '@/lib/webscan/parse/testssl';
import { certCovers, parseTlsx, TLSX_TITLES } from '@/lib/webscan/parse/tlsx';
import { dedupeAcrossScanners } from '@/lib/webscan/parse';
import type { NormalizedFinding, ParseContext } from '@/lib/webscan/parse/types';
import { HTTPX_OUT, NUCLEI_OUT, TESTSSL_OUT, TLSX_OUT, WEAK_CIPHERS_OUT } from '../fixtures/webscan';

// 用現在時間：範例的憑證到期日也是相對於現在（3.5 天後）
const ctx: ParseContext = { url: 'https://shop.example.com/', host: 'shop.example.com', port: 443, scheme: 'https', now: new Date() };

describe('webscan parsers', () => {
  it('httpx: fingerprint only, plus no-https on plain http sites', () => {
    const r = parseHttpx(HTTPX_OUT, ctx);
    expect(r.findings).toEqual([]);
    expect(r.fingerprint).toMatchObject({ status_code: 200, title: 'Shop', webserver: 'nginx', tech: ['Nginx', 'PHP'], ip: '93.184.216.34' });
    const http = parseHttpx(HTTPX_OUT, { ...ctx, scheme: 'http', url: 'http://shop.example.com/', port: 80 });
    expect(http.findings.map((f) => f.rule)).toEqual(['web.no_https']);
    expect(parseHttpx('', ctx).warnings).toEqual(['httpx:no_output']);
  });

  it('tlsx: expiring, self-signed and old protocol', () => {
    const r = parseTlsx(TLSX_OUT, ctx);
    expect(r.findings.map((f) => [f.rule, f.severity])).toEqual([
      ['tls.cert_expiring', 'high'],
      ['tls.cert_self_signed', 'medium'],
      ['tls.old_protocol', 'medium'],
    ]);
    const expired = parseTlsx(JSON.stringify({ probe_status: true, not_after: '2026-01-01T00:00:00Z', expired: true }), ctx);
    expect(expired.findings.map((f) => f.rule)).toEqual(['tls.cert_expired']);
    expect(parseTlsx(JSON.stringify({ probe_status: false, error: 'timeout' }), ctx).warnings[0]).toMatch(/^tlsx:failed/);
  });

  it('tlsx: the name check uses the certificate names, not tlsx\'s mismatched flag (it compares against the pinned IP)', () => {
    const ok = parseTlsx(JSON.stringify({ probe_status: true, subject_cn: 'example.com', subject_an: ['*.example.com', 'example.com'], mismatched: true }), ctx);
    expect(ok.findings.map((f) => f.rule)).toEqual([]);
    const bad = parseTlsx(JSON.stringify({ probe_status: true, subject_cn: 'other.example.net', subject_an: ['other.example.net'] }), ctx);
    expect(bad.findings.map((f) => f.rule)).toEqual(['tls.cert_mismatch']);
    expect(certCovers('shop.example.com', ['*.example.com'])).toBe(true);
    expect(certCovers('a.shop.example.com', ['*.example.com'])).toBe(false);
    expect(certCovers('example.com', ['*.example.com'])).toBe(false);
    expect(certCovers('Shop.Example.com.', ['shop.example.com'])).toBe(true);
    expect(certCovers('203.0.113.7', ['*.0.113.7'])).toBe(false);
    expect(certCovers('203.0.113.7', ['203.0.113.7'])).toBe(true);
  });

  it('nuclei: classification, dedupe, broken lines skipped, secrets masked', () => {
    const r = parseNuclei(NUCLEI_OUT, ctx);
    expect(r.findings).toHaveLength(2);
    const cve = r.findings.find((f) => f.rule === 'nuclei:CVE-2021-41773')!;
    expect(cve).toMatchObject({ severity: 'high', cve: 'CVE-2021-41773', cwe: ['CWE-22'], cvss: 7.5 });
    expect((cve.evidence.extracted as string[])[1]).toBe('AKIA…34');
    expect(cve.evidence.epss).toBe(0.97);
    expect(parseNuclei(`${NUCLEI_OUT}\n${NUCLEI_OUT}`, ctx).findings).toHaveLength(2);
    expect(maskSecret('short')).toBe('short');
  });

  it('testssl: LOW and above become findings, WARN becomes a warning', () => {
    const r = parseTestssl(TESTSSL_OUT, ctx);
    expect(r.findings.map((f) => [f.rule, f.severity])).toEqual([
      ['testssl:TLS1', 'low'],
      ['testssl:BREACH', 'medium'],
      ['testssl:some_new_check', 'high'],
    ]);
    expect(r.findings[1]).toMatchObject({ cve: 'CVE-2013-3587', cwe: ['CWE-310'], title: TESTSSL_TITLES.BREACH });
    expect(r.findings[2]!.title).toBe('testssl: some_new_check');
    expect(r.warnings).toEqual(['testssl:warn:engine_problem:No engine or GOST support']);
    expect(parseTestssl('{not json', ctx).warnings).toEqual(['testssl:bad_json']);
    const pretty = JSON.stringify({ scanResult: [{ protocols: [{ id: 'TLS1_1', port: '443', severity: 'LOW', finding: 'offered' }] }] });
    expect(parseTestssl(pretty, ctx).findings.map((f) => f.rule)).toEqual(['testssl:TLS1_1']);
  });

  it('testssl noise: one finding for all weak ciphers, one for cipher order, no overall grade', () => {
    const r = parseTestssl(WEAK_CIPHERS_OUT, ctx);
    expect(r.findings.map((f) => [f.rule, f.severity])).toEqual([
      ['testssl:cipher_order', 'low'],
      ['testssl:weak_ciphers', 'medium'],
    ]);
    const weak = r.findings[1]!;
    expect(weak.evidence.count).toBe(3);
    expect(weak.title).toBe(TESTSSL_TITLES.weak_ciphers);
  });

  it('a certificate problem tlsx already reported is not repeated from testssl', () => {
    const f = (rule: string) => ({ rule }) as NormalizedFinding;
    const kept = dedupeAcrossScanners([f('tls.cert_expiring'), f('testssl:cert_notAfter'), f('testssl:cert_expirationStatus'), f('tls.cert_self_signed'), f('testssl:cert_chain_of_trust'), f('testssl:BREACH')]);
    expect(kept.map((x) => x.rule)).toEqual(['tls.cert_expiring', 'tls.cert_self_signed', 'testssl:BREACH']);
    // tlsx 沒抓到（例如沒跑）時 testssl 的照留
    expect(dedupeAcrossScanners([f('testssl:cert_chain_of_trust')]).map((x) => x.rule)).toEqual(['testssl:cert_chain_of_trust']);
  });

  it('every hub-generated title and recommendation has an English translation', () => {
    const texts = [
      ...Object.values(HTTPX_TITLES),
      ...Object.values(TLSX_TITLES),
      ...Object.values(TESTSSL_TITLES),
      ...parseHttpx(HTTPX_OUT, { ...ctx, scheme: 'http' }).findings.map((f) => f.recommendation),
      ...parseTlsx(TLSX_OUT, ctx).findings.map((f) => f.recommendation),
      ...parseTlsx(JSON.stringify({ probe_status: true, expired: true, subject_an: ['other.example.net'] }), ctx).findings.map((f) => f.recommendation),
      ...parseTestssl(WEAK_CIPHERS_OUT, ctx).findings.map((f) => f.recommendation),
    ];
    const missing = [...new Set([...texts, ...Object.values(BLOCK_REASONS), ...Object.values(ERROR_TEXTS)])].filter((zh) => zh && !en[zh]);
    expect(missing).toEqual([]);
  });
});
