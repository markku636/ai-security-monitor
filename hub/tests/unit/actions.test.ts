import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkTarget, parseAction } from '@/lib/actions/kinds';
import { actionKeyFor, canonical, paramsHash, tokenFor } from '@/lib/actions/sign';

const FIXTURE = path.resolve(__dirname, '../../../contract/action.v1.json');

describe('canonical JSON', () => {
  it('sorts object keys recursively, keeps arrays, drops undefined', () => {
    expect(canonical({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 'x' }, u: undefined })).toBe('{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}');
    expect(canonical('a"b\\c\n')).toBe(JSON.stringify('a"b\\c\n'));
    expect(paramsHash({ ip: '1.2.3.4', direction: 'both' })).toBe(paramsHash({ direction: 'both', ip: '1.2.3.4' }));
  });
});

describe('action kinds', () => {
  it('validates targets like the agent does', () => {
    expect(checkTarget('198.51.100.7')).toBeNull();
    expect(checkTarget('198.51.100.0/24')).toBeNull();
    expect(checkTarget('2001:db8::/32')).toBeNull();
    expect(checkTarget('127.0.0.1')).toBe('target_reserved');
    expect(checkTarget('0.0.0.0/0')).toBe('target_too_broad');
    expect(checkTarget('10.0.0.0/8')).toBe('target_too_broad');
    expect(checkTarget('224.0.0.1')).toBe('target_reserved');
    expect(checkTarget('::1')).toBe('target_reserved');
    expect(checkTarget('example.com')).toBe('bad_target');
    expect(checkTarget('1.2.3.4/33')).toBe('bad_target');
  });

  it('parses params per kind and rejects extras', () => {
    expect(parseAction('block_ip', { ip: ' 198.51.100.7 ' })).toEqual({ ok: true, kind: 'block_ip', params: { ip: '198.51.100.7', direction: 'both' } });
    expect(parseAction('block_ip', { ip: '198.51.100.7', evil: 1 })).toEqual({ ok: false, error: 'bad_params' });
    expect(parseAction('close_port', { proto: 'tcp', port: 6379 })).toMatchObject({ ok: true });
    expect(parseAction('close_port', { proto: 'tcp', port: 0 })).toMatchObject({ ok: false });
    expect(parseAction('kill_process', {})).toEqual({ ok: false, error: 'unknown_kind' });
  });
});

describe('contract/action.v1.json (shared with the Rust agent)', () => {
  const signing = 'asa-contract-test-signing-key';
  const agentId = '0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee';
  const fields = {
    action_id: 'act_00112233445566ff',
    agent_id: agentId,
    kind: 'block_ip',
    // 故意不照字母順序：canonical 要排序
    params: { reason: 'abusech-feodo', ip: '203.0.113.66', direction: 'both' },
    expires_at: '2026-10-17T09:30:00.000Z',
  };
  const actionKey = actionKeyFor(signing, agentId);
  const expected = {
    signing_key: signing,
    agent_id: agentId,
    action_key: actionKey,
    canonical: canonical(fields),
    action: { ...fields, reason: 'Feodo C2', destructive: false, token: tokenFor(actionKey, fields) },
  };

  it('matches the committed fixture', () => {
    if (process.env.ASA_UPDATE_CONTRACT === '1') {
      fs.writeFileSync(FIXTURE, `${JSON.stringify(expected, null, 2)}\n`);
    }
    expect(JSON.parse(fs.readFileSync(FIXTURE, 'utf8'))).toEqual(expected);
  });
});

describe('agent-proposed params', () => {
  it('accepts the shapes the agent proposes', () => {
    expect(parseAction('block_ip', { ip: '203.0.113.66', direction: 'inbound', reason: 'x'.repeat(300) })).toMatchObject({
      ok: true,
      params: { ip: '203.0.113.66', direction: 'in', reason: 'x'.repeat(120) },
    });
    expect(parseAction('close_port', { proto: 'tcp', port: 6379, direction: 'inbound' })).toMatchObject({ ok: true });
  });
});
