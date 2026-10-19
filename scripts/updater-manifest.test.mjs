import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import test from 'node:test';
import { buildManifest, TARGETS } from './updater-manifest.mjs';

function fixture() {
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'asm-updater-'));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const id = crypto.randomBytes(8);
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const pubkey = Buffer.from('untrusted comment: test\n' + Buffer.concat([Buffer.from('Ed'), id, raw]).toString('base64')).toString('base64');
  for (const target of TARGETS('1.2.3')) {
    const bytes = Buffer.from(target.file);
    fs.writeFileSync(path.join(dist, target.file), bytes);
    const sig = Buffer.concat([Buffer.from('Ed'), id, crypto.sign(null, bytes, privateKey)]);
    fs.writeFileSync(path.join(dist, target.file + '.sig'), Buffer.from('untrusted comment: test\n' + sig.toString('base64')).toString('base64'));
  }
  return { version: '1.2.3', dist, repo: 'test/repo', pubkey, notes: 'test' };
}

test('release includes signed native updates for Ubuntu and both Mac architectures', () => {
  const input = fixture();
  try {
    const m = buildManifest(input);
    assert.match(m.platforms['linux-x86_64-deb'].url, /\.deb$/);
    assert.match(m.platforms['linux-x86_64-appimage'].url, /\.AppImage$/);
    for (const arch of ['aarch64', 'x86_64']) assert.match(m.platforms[`darwin-${arch}-app`].url, /\.app\.tar\.gz$/);
    assert.equal(m.platforms['linux-x86_64'], undefined);
    fs.unlinkSync(path.join(input.dist, TARGETS(input.version).at(-1).file + '.sig'));
    assert.throws(() => buildManifest(input), /missing updater artifacts or signatures/);
  } finally { fs.rmSync(input.dist, { recursive: true, force: true }); }
});

test('tampered Debian update is rejected before publishing', () => {
  const input = fixture();
  try {
    fs.appendFileSync(path.join(input.dist, TARGETS(input.version).at(-1).file), 'tampered');
    assert.throws(() => buildManifest(input), /signature does not verify/);
  } finally { fs.rmSync(input.dist, { recursive: true, force: true }); }
});
