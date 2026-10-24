// contract/webscan-*.v1.json：runner 送的格式（Rust 測試產生）與 Hub 交給 runner 的格式，兩邊驗同一份檔案。
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ClaimRequest, ClaimResponse, HeartbeatBody, JobSpec, ResultBody } from '@/lib/webscan/contract';
import { pickScanners, stepFor } from '@/lib/webscan/jobs';
import { defaultWebscanSettings } from '@/lib/webscan/settings';

const load = (name: string) => JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../../contract', name), 'utf8'));

describe('webscan contract', () => {
  it('accepts the runner payloads', () => {
    expect(ClaimRequest.safeParse(load('webscan-claim.v1.json')).success).toBe(true);
    expect(HeartbeatBody.safeParse(load('webscan-heartbeat.v1.json')).success).toBe(true);
    expect(ResultBody.safeParse(load('webscan-result.v1.json')).success).toBe(true);
  });

  it('the claim response example matches what the hub produces', () => {
    const p = ClaimResponse.safeParse(load('webscan-job.v1.json'));
    expect(p.success, JSON.stringify(p.error?.issues)).toBe(true);
    const scan = load('webscan-job.v1.json').jobs[0];
    expect(scan.steps).toEqual(pickScanners({ scheme: 'https' }, 'active_light', defaultWebscanSettings(), 'noncommercial').map(stepFor));
  });

  it('rejects unknown scanner options and unknown fields (runner has the same allowlist)', () => {
    const job = load('webscan-job.v1.json').jobs[0];
    const bad = structuredClone(job);
    bad.steps[2].options.templates = '/etc';
    expect(JobSpec.safeParse(bad).success).toBe(false);
    const extra = structuredClone(job);
    extra.target.args = ['-x'];
    expect(JobSpec.safeParse(extra).success).toBe(false);
    const noDos = structuredClone(job);
    noDos.steps[2].options.exclude_tags = [];
    expect(JobSpec.safeParse(noDos).success).toBe(false);
  });

  it('plain http targets skip TLS checks; passive runs only passive scanners', () => {
    const s = defaultWebscanSettings();
    expect(pickScanners({ scheme: 'http' }, 'active_light', s, 'noncommercial')).toEqual(['httpx', 'nuclei']);
    expect(pickScanners({ scheme: 'https' }, 'passive', s, 'noncommercial')).toEqual(['httpx', 'tlsx']);
    expect(pickScanners({ scheme: 'https' }, 'active_light', { ...s, disabled_scanners: ['testssl'] }, 'commercial')).toEqual(['httpx', 'tlsx', 'nuclei']);
  });
});
