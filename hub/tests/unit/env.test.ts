import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { envAliases, loadEnv, readEnv } from '@/lib/env';

const KEYS = [
  'AI_SECURITY_MONITOR_HUB_ADMIN_SECRET',
  'AI_SECURITY_MONITOR_HUB_ADMIN_SECRET_FILE',
  'ASA_HUB_ADMIN_SECRET',
  'ASA_HUB_ADMIN_SECRET_FILE',
  'AI_SECURITY_MONITOR_HUB_EDITION',
  'ASA_HUB_EDITION',
];
const saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));

afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

function clear() {
  for (const k of KEYS) delete process.env[k];
}

describe('env aliases (ai-security-monitor rename)', () => {
  it('lists the new name before the legacy one', () => {
    expect(envAliases('ASA_HUB_ADMIN_SECRET')).toEqual(['AI_SECURITY_MONITOR_HUB_ADMIN_SECRET', 'ASA_HUB_ADMIN_SECRET']);
    expect(envAliases('PORT')).toEqual(['PORT']);
  });

  it('prefers the new name, falls back to the legacy one', () => {
    clear();
    process.env.ASA_HUB_ADMIN_SECRET = 'legacy';
    expect(readEnv('ASA_HUB_ADMIN_SECRET')).toBe('legacy');
    process.env.AI_SECURITY_MONITOR_HUB_ADMIN_SECRET = 'new';
    expect(readEnv('ASA_HUB_ADMIN_SECRET')).toBe('new');
    process.env.AI_SECURITY_MONITOR_HUB_EDITION = 'server';
    expect(loadEnv()).toMatchObject({ adminSecret: 'new', edition: 'server' });
  });

  it('reads _FILE for either name; an empty new name does not hide the legacy one', () => {
    clear();
    const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hub-env-')), 'secret');
    fs.writeFileSync(f, 'from-file\n');
    process.env.AI_SECURITY_MONITOR_HUB_ADMIN_SECRET = '  ';
    process.env.ASA_HUB_ADMIN_SECRET_FILE = f;
    expect(readEnv('ASA_HUB_ADMIN_SECRET')).toBe('from-file');
    process.env.AI_SECURITY_MONITOR_HUB_ADMIN_SECRET_FILE = f;
    process.env.ASA_HUB_ADMIN_SECRET = 'legacy';
    expect(readEnv('ASA_HUB_ADMIN_SECRET')).toBe('from-file');
  });
});
