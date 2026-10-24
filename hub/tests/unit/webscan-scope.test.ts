import { afterEach, describe, expect, it } from 'vitest';
import { classifyIp, forbiddenHost, parseTargetUrl, resolveAndScreen, screenIps, setSelfIpsForTests, setWebscanLookupForTests } from '@/lib/webscan/scope';

afterEach(() => {
  setWebscanLookupForTests(null);
  setSelfIpsForTests(null);
});

describe('webscan: target URL parsing', () => {
  it('normalizes scheme, host, port and path; bare hosts become https', () => {
    expect(parseTargetUrl('Shop.Example.COM')).toEqual({ url: 'https://shop.example.com/', scheme: 'https', host: 'shop.example.com', port: 443, path: '/' });
    expect(parseTargetUrl('http://shop.example.com:8080/app?x=1#y')).toMatchObject({ url: 'http://shop.example.com:8080/app', port: 8080, path: '/app' });
    expect(parseTargetUrl('https://shop.example.com:443/')).toMatchObject({ url: 'https://shop.example.com/', port: 443 });
    expect(parseTargetUrl('https://[2001:db8::1]:8443/')).toMatchObject({ host: '2001:db8::1', url: 'https://[2001:db8::1]:8443/' });
    expect(parseTargetUrl('https://shop.example.com./')).toMatchObject({ host: 'shop.example.com' });
  });

  it('rejects other schemes, credentials, junk and forbidden hosts', () => {
    expect(parseTargetUrl('ftp://shop.example.com/')).toEqual({ error: 'bad_scheme' });
    expect(parseTargetUrl('javascript:alert(1)')).toEqual({ error: 'bad_url' });
    expect(parseTargetUrl('https://user:pw@shop.example.com/')).toEqual({ error: 'url_credentials' });
    expect(parseTargetUrl('https://shop example.com/')).toEqual({ error: 'bad_url' });
    expect(parseTargetUrl('https://shop.example.com/"><script>')).toEqual({ error: 'bad_url' });
    expect(parseTargetUrl('-u http://x')).toEqual({ error: 'bad_url' });
    expect(parseTargetUrl('')).toEqual({ error: 'bad_url' });
    expect(parseTargetUrl(`https://a.example/${'x'.repeat(2100)}`)).toEqual({ error: 'url_too_long' });
    for (const h of ['localhost', 'app.localhost', 'metadata.google.internal', 'hub', 'postgres']) {
      expect(parseTargetUrl(`http://${h}/`)).toEqual({ error: 'forbidden_host' });
      expect(forbiddenHost(h)).toBe(true);
    }
  });
});

describe('webscan: address screening', () => {
  const opts = { internalCidrs: ['192.168.50.0/24', 'fd12:3456::/32'] };

  it('classifies the always-forbidden ranges', () => {
    expect(classifyIp('169.254.169.254')).toBe('metadata');
    expect(classifyIp('100.100.100.200')).toBe('metadata');
    expect(classifyIp('fd00:ec2::254')).toBe('metadata');
    expect(classifyIp('127.0.0.1')).toBe('loopback');
    expect(classifyIp('::1')).toBe('loopback');
    expect(classifyIp('::ffff:127.0.0.1')).toBe('loopback');
    expect(classifyIp('0.0.0.0')).toBe('unspecified');
    expect(classifyIp('169.254.10.10')).toBe('link_local');
    expect(classifyIp('fe80::1')).toBe('link_local');
    expect(classifyIp('224.0.0.251')).toBe('multicast');
    expect(classifyIp('203.0.113.10')).toBe('reserved');
    expect(classifyIp('2002:7f00:1::')).toBe('reserved');
    expect(classifyIp('64:ff9b::7f00:1')).toBe('reserved');
    expect(classifyIp('10.1.2.3')).toBe('private');
    expect(classifyIp('100.64.1.1')).toBe('private');
    expect(classifyIp('93.184.216.34')).toBeNull();
    expect(classifyIp('not-an-ip')).toBe('invalid_ip');
  });

  it('allows public addresses and private ones inside the allowlist only', () => {
    expect(screenIps(['93.184.216.34'], opts)).toEqual({ ok: true, ips: ['93.184.216.34'], internal: false });
    expect(screenIps(['192.168.50.10'], opts)).toEqual({ ok: true, ips: ['192.168.50.10'], internal: true });
    expect(screenIps(['fd12:3456::10'], opts)).toMatchObject({ ok: true, internal: true });
    expect(screenIps(['10.0.0.5'], opts)).toEqual({ ok: false, reason: 'private_not_allowed', ip: '10.0.0.5' });
  });

  it('rejects the whole set when any address fails (no picking the good one)', () => {
    expect(screenIps(['93.184.216.34', '127.0.0.1'], opts)).toMatchObject({ ok: false, reason: 'loopback' });
    expect(screenIps(['93.184.216.34', '169.254.169.254'], opts)).toMatchObject({ ok: false, reason: 'metadata' });
    expect(screenIps([], opts)).toEqual({ ok: false, reason: 'unresolvable' });
    expect(screenIps(['93.184.216.34'], { ...opts, selfIps: ['93.184.216.34'] })).toMatchObject({ ok: false, reason: 'self' });
  });

  it('resolves names before screening and blocks names that rebind to internal addresses', async () => {
    setSelfIpsForTests([]);
    const dns: Record<string, string[]> = { 'shop.example.com': ['93.184.216.34'], 'evil.example.net': ['93.184.216.34', '127.0.0.1'], 'intranet.corp': ['192.168.50.20'] };
    setWebscanLookupForTests(async (h) => {
      if (!dns[h]) throw new Error('ENOTFOUND');
      return dns[h];
    });
    expect(await resolveAndScreen('shop.example.com', opts)).toEqual({ ok: true, ips: ['93.184.216.34'], internal: false });
    expect(await resolveAndScreen('evil.example.net', opts)).toMatchObject({ ok: false, reason: 'loopback' });
    expect(await resolveAndScreen('intranet.corp', opts)).toMatchObject({ ok: true, internal: true });
    expect(await resolveAndScreen('nowhere.example', opts)).toEqual({ ok: false, reason: 'unresolvable' });
    expect(await resolveAndScreen('metadata.google.internal', opts)).toEqual({ ok: false, reason: 'forbidden_host' });
    setSelfIpsForTests(['192.168.50.20']);
    expect(await resolveAndScreen('intranet.corp', opts)).toMatchObject({ ok: false, reason: 'self' });
  });
});
