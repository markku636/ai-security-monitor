// MITRE ATT&CK／法規對應：對應表本身的一致性、問題頁的手法／法規篩選、/mitre 的彙總。
import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { POST as register } from '@/app/api/v1/agents/register/route';
import { POST as report } from '@/app/api/v1/ingest/report/route';
import { CONTROLS, TACTICS, TECHNIQUES, techniqueUrl } from '@/lib/attack/catalog';
import { RULE_MAP, mapRule, ruleHasControl, ruleHasTechnique } from '@/lib/attack/mapping';
import { resetEnvForTests } from '@/lib/env';
import { attackSummary } from '@/lib/queries/attack';
import { listFindings, parseFindingFilter, toFindingView } from '@/lib/queries/findings';
import { createTestDb } from '../helpers/db';

const CONTRACT = path.resolve(__dirname, '../../../contract');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CONTRACT, name), 'utf8'));

function clientPost(pathname: string, body: unknown) {
  return new Request(`http://localhost:3000${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer client-a' },
    body: JSON.stringify(body),
  });
}

describe('mapping table', () => {
  it('only uses techniques, tactics and controls that exist in the catalog', () => {
    const tactics = new Set(TACTICS.map((x) => x.id));
    for (const [id, tech] of Object.entries(TECHNIQUES)) {
      expect(id).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(tech.tactics.length).toBeGreaterThan(0);
      for (const tac of tech.tactics) expect(tactics.has(tac)).toBe(true);
    }
    for (const [rule, m] of Object.entries(RULE_MAP)) {
      for (const id of m.mitre) expect(TECHNIQUES[id], `${rule} → ${id}`).toBeDefined();
      for (const c of m.compliance) expect(CONTROLS[c], `${rule} → ${c}`).toBeDefined();
      expect(new Set(m.compliance).size, `${rule} has duplicate controls`).toBe(m.compliance.length);
    }
  });

  it('prefers an exact rule over a prefix and the longest prefix over shorter ones', () => {
    expect(mapRule('hardening.lin.fs.suid_dumpable').mitre).toEqual(['T1003']);
    expect(mapRule('hardening.lin.fs.protected_symlinks').mitre).toEqual(['T1068']);
    expect(mapRule('firewall.anything_new').mitre).toEqual(['T1562.004']);
    expect(mapRule('vuln.app.7zip-cve-2025-0411').mitre).toEqual(['T1203']);
    expect(mapRule('metrics.disk_full')).toEqual({ mitre: [], compliance: [] });
    // 子技術算進上層技術；框架名稱篩整個框架
    expect(ruleHasTechnique('events.audit_log_cleared', 'T1070')).toBe(true);
    expect(ruleHasTechnique('events.audit_log_cleared', 'T1070.001')).toBe(true);
    expect(ruleHasTechnique('events.audit_log_cleared', 'T107')).toBe(false);
    expect(ruleHasControl('vuln.os_eol', 'iso27001:A.8.8')).toBe(true);
    expect(ruleHasControl('vuln.os_eol', 'iso27001')).toBe(true);
    expect(ruleHasControl('vuln.os_eol', 'cis8:4.4')).toBe(false);
    expect(techniqueUrl('T1053.005')).toBe('https://attack.mitre.org/techniques/T1053/005/');
  });
});

describe('findings filters and the /mitre summary', () => {
  beforeAll(async () => {
    await createTestDb();
    process.env.ASA_HUB_ADMIN_SECRET = 'test-admin';
    process.env.ASA_HUB_CLIENT_SECRETS = 'client-a';
    process.env.ASA_HUB_INGEST_MIN_INTERVAL_MS = '0';
    resetEnvForTests();
    await register(clientPost('/api/v1/agents/register', load('register.v1.json')));
    const rep = load('report.v1.json');
    rep.finished_at = new Date().toISOString();
    const base = rep.findings[0];
    const extra = (id: string, rule: string, scanner: string) => ({ ...structuredClone(base), id, rule, scanner, intel_hits: [], actions: [] });
    rep.findings.push(extra('f_00000000000000a1', 'hardening.lin.fs.suid_dumpable', 'hardening'), extra('f_00000000000000a2', 'metrics.disk_full', 'metrics'));
    expect((await report(clientPost('/api/v1/ingest/report', rep))).status).toBe(200);
  });

  it('tags each finding with its techniques and controls', async () => {
    const r = await listFindings(parseFindingFilter({}));
    const intel = r.items.map(toFindingView).find((f) => f.rule === 'intel.outbound_match')!;
    expect(intel.mitre).toEqual(['T1071']);
    expect(intel.compliance).toContain('iso27001:A.8.16');
  });

  it('filters by technique (with sub-techniques) and by control or framework', async () => {
    const rules = async (p: Record<string, string>) => (await listFindings(parseFindingFilter(p))).items.map((f) => f.rule).sort();
    expect(await rules({ technique: 'T1071' })).toEqual(['intel.outbound_match']);
    expect(await rules({ technique: 'T1190' })).toEqual(['ports.exposed_open']);
    // 精確對應優先：suid_dumpable 是 T1003，不會被 hardening.lin.fs.* 的 T1068 撈到
    expect(await rules({ technique: 'T1068' })).toEqual([]);
    expect(await rules({ technique: 'T1003' })).toEqual(['hardening.lin.fs.suid_dumpable']);
    expect(await rules({ control: 'pci4:1.2.1' })).toEqual(['ports.exposed_open']);
    expect((await rules({ control: 'iso27001' })).length).toBe(3);
    expect(await rules({ technique: 'T9999' })).toEqual([]);
    // 格式不對的參數忽略
    expect(parseFindingFilter({ technique: "T1071' or 1=1", control: '<x>' })).toMatchObject({ technique: undefined, control: undefined });
  });

  it('summarises techniques (rolling sub-techniques up), controls and unmapped findings', async () => {
    const s = await attackSummary('30');
    expect(s.total).toBe(4);
    expect(s.unmapped).toBe(1);
    expect(s.techniques.T1071).toMatchObject({ findings: 1, hosts: 1, rules: ['intel.outbound_match'] });
    expect(s.techniques.T1190.findings).toBe(1);
    expect(s.techniques.T1003.findings).toBe(1);
    expect(s.controls['pci4:1.2.1']).toMatchObject({ findings: 1, hosts: 1 });
    expect((await attackSummary('30', 'no-such-agent')).total).toBe(0);
  });
});
