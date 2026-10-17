// 「辦公室的電腦找得到這個 Hub 嗎？」的判斷，以及主機的「有新版」徽章。
import { describe, expect, it } from 'vitest';
import { updateHowText } from '@/components/security/UpdateBadge';
import { discoveryReport, isLoopbackHost, type DiscoveryInput } from '@/lib/discovery/status';
import { makeT } from '@/lib/i18n/core';
import { agentNewVersion } from '@/lib/update';

const t = makeT('zh-TW');
const en = makeT('en');

const base: DiscoveryInput = {
  edition: 'standalone',
  bind: '',
  publicUrl: 'http://127.0.0.1:8088',
  inDocker: true,
  mdns: { enabled: false, running: false },
  advertisers: [],
  srv: { checked: false, found: false },
};

describe('discovery status', () => {
  it('standalone on 127.0.0.1 is neither reachable nor findable', () => {
    const r = discoveryReport(base, t);
    expect(r.reachable).toBe(false);
    expect(r.findable).toBe(false);
    expect(r.level).toBe('bad');
    expect(r.summary).toContain('找不到、也連不到');
    expect(r.checks.find((c) => c.id === 'reach')?.level).toBe('bad');
    expect(r.checks.find((c) => c.id === 'url')?.level).toBe('bad');
    // 英文介面也有完整句子
    expect(discoveryReport(base, en).summary).toMatch(/cannot|neither/i);
  });

  it('explicit bind 0.0.0.0 with a LAN URL is reachable; advertiser makes it findable', () => {
    const lan: DiscoveryInput = { ...base, bind: '0.0.0.0', publicUrl: 'http://192.168.1.10:8088' };
    const r = discoveryReport(lan, t);
    expect(r.reachable).toBe(true);
    expect(r.findable).toBe(false);
    expect(r.level).toBe('warn');
    // Docker 裡 Hub 自己的廣播不算數；有電腦幫忙廣播（指紋相符）才算
    const withAd = discoveryReport(
      { ...lan, mdns: { enabled: true, running: true }, advertisers: [{ hostname: 'PC-01', url: 'http://192.168.1.10:8088', fingerprintOk: true, at: new Date() }] },
      t,
    );
    expect(withAd.findable).toBe(true);
    expect(withAd.level).toBe('ok');
    expect(withAd.checks.find((c) => c.id === 'advertiser')?.text).toContain('PC-01');
    // 廣播的是別的 Hub：不算，另外提醒
    const wrong = discoveryReport({ ...lan, advertisers: [{ hostname: 'OLD', url: 'http://x', fingerprintOk: false, at: new Date() }] }, t);
    expect(wrong.findable).toBe(false);
    expect(wrong.checks.some((c) => c.title.includes('不是這個 Hub'))).toBe(true);
  });

  it('server edition outside Docker with mDNS running, or an SRV record, is findable', () => {
    const srv: DiscoveryInput = { ...base, edition: 'server', inDocker: false, publicUrl: 'https://hub.corp.example', mdns: { enabled: true, running: true } };
    expect(discoveryReport(srv, t).findable).toBe(true);
    const dnsOnly = discoveryReport({ ...srv, inDocker: true, srv: { checked: true, found: true, name: '_aisecmon._tcp.corp.example', target: 'hub.corp.example', port: 443 } }, t);
    expect(dnsOnly.findable).toBe(true);
    expect(dnsOnly.checks.find((c) => c.id === 'srv')?.text).toContain('hub.corp.example:443');
  });

  it('loopback detection', () => {
    for (const h of ['127.0.0.1', 'localhost', '[::1]', '127.1.2.3', 'hub.localhost']) expect(isLoopbackHost(h)).toBe(true);
    for (const h of ['0.0.0.0', '192.168.1.5', 'hub.corp.example', '::']) expect(isLoopbackHost(h)).toBe(false);
  });
});

describe('agent update badge', () => {
  it('uses the newer of the agent-reported and hub-known latest versions', () => {
    expect(agentNewVersion('0.3.0', { latest: '0.4.0' }, null)).toBe('0.4.0');
    expect(agentNewVersion('0.3.0', null, '0.4.1')).toBe('0.4.1');
    expect(agentNewVersion('0.3.0', { latest: '0.4.0' }, '0.4.1')).toBe('0.4.1');
    expect(agentNewVersion('0.4.1', { latest: '0.4.1' }, '0.4.0')).toBeNull();
    expect(agentNewVersion('0.4.0', { latest: '0.4.0-rc1' }, null)).toBeNull();
    expect(agentNewVersion('', { latest: '9.9.9' }, null)).toBeNull();
  });

  it('explains how each host gets updated', () => {
    expect(updateHowText(t, { owner: 'desktop', mode: 'notify' })).toContain('桌面版');
    expect(updateHowText(t, { owner: 'agent', mode: 'auto' })).toContain('自動更新');
    expect(updateHowText(t, { owner: 'agent', mode: 'notify' })).toContain('self-update --yes');
    expect(updateHowText(t, null)).toContain('self-update --yes');
  });
});
