// 桌面版自動更新的 latest.json（tauri-plugin-updater 的格式），release.yml 用。
// 讀 dist/ 裡的更新檔與 minisign 簽章（.sig），先用 tauri.conf.json 的公鑰逐一驗章——簽章和 App 內建的公鑰對不上
// （例如 GitHub secret 換成別把金鑰）就失敗，不讓一個裝不上的更新發出去——再寫出 dist/latest.json。
// 用法：node scripts/updater-manifest.mjs <version> <dist-dir> [--repo owner/name] [--allow-missing]
//
// 平台鍵（App 先找 {os}-{arch}-{安裝方式}，找不到才用 {os}-{arch}）：
//   windows-x86_64(-nsis)   AI-Security-Monitor-<v>-windows-x64-setup.exe
//   darwin-aarch64(-app)    AI-Security-Monitor-<v>-macos-arm64.app.tar.gz
//   darwin-x86_64(-app)     AI-Security-Monitor-<v>-macos-x64.app.tar.gz
//   linux-x86_64-appimage   AI-Security-Monitor-<v>-linux-x64.AppImage
//   linux-x86_64-deb        AI-Security-Monitor-<v>-linux-amd64.deb（有 .deb.sig 才加；安裝要系統管理員密碼）
// Linux 刻意不放沒有安裝方式的 linux-x86_64：.deb 安裝找不到自己的項目時就不更新，不會誤拿到 AppImage。
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { changelogSection } from './changelog-section.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** minisign 公鑰（tauri.conf.json 的 pubkey 是整個公鑰檔再 base64 一次）→ { keyId, key }。 */
export function parsePublicKey(b64) {
  const text = Buffer.from(b64.trim(), 'base64').toString('utf8');
  const line = text.split(/\r?\n/).find((l) => l && !l.startsWith('untrusted comment:'));
  const raw = Buffer.from(line ?? '', 'base64');
  if (raw.length !== 42 || raw.subarray(0, 2).toString() !== 'Ed') throw new Error('not a minisign Ed25519 public key');
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw.subarray(10)]);
  return { keyId: raw.subarray(2, 10), key: crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }) };
}

/** 驗一個檔案的 minisign 簽章（.sig 內容是整個簽章檔再 base64 一次）。不符就丟錯。 */
export function verifySignature(fileBytes, sigB64, pub) {
  const lines = Buffer.from(sigB64.trim(), 'base64').toString('utf8').split(/\r?\n/);
  const sigLine = lines.find((l, i) => i > 0 && l && !l.includes(':'));
  const trusted = lines.find((l) => l.startsWith('trusted comment: '));
  const globalLine = lines[lines.indexOf(trusted) + 1];
  const sig = Buffer.from(sigLine ?? '', 'base64');
  if (sig.length !== 74) throw new Error('malformed signature');
  const alg = sig.subarray(0, 2).toString();
  if (!sig.subarray(2, 10).equals(pub.keyId)) throw new Error('signed with a different key (key id mismatch)');
  const msg = alg === 'ED' ? crypto.createHash('blake2b512').update(fileBytes).digest() : alg === 'Ed' ? fileBytes : null;
  if (!msg) throw new Error(`unknown signature algorithm ${alg}`);
  if (!crypto.verify(null, msg, pub.key, sig.subarray(10))) throw new Error('signature does not verify');
  // trusted comment 的簽章：sig || comment
  if (trusted && globalLine) {
    const g = Buffer.from(globalLine, 'base64');
    const comment = Buffer.from(trusted.slice('trusted comment: '.length), 'utf8');
    if (!crypto.verify(null, Buffer.concat([sig.subarray(10), comment]), pub.key, g)) throw new Error('trusted comment signature does not verify');
  }
  return alg;
}

export const TARGETS = (v) => [
  { keys: ['windows-x86_64', 'windows-x86_64-nsis'], file: `AI-Security-Monitor-${v}-windows-x64-setup.exe` },
  { keys: ['darwin-aarch64', 'darwin-aarch64-app'], file: `AI-Security-Monitor-${v}-macos-arm64.app.tar.gz` },
  { keys: ['darwin-x86_64', 'darwin-x86_64-app'], file: `AI-Security-Monitor-${v}-macos-x64.app.tar.gz` },
  { keys: ['linux-x86_64-appimage'], file: `AI-Security-Monitor-${v}-linux-x64.AppImage` },
  { keys: ['linux-x86_64-deb'], file: `AI-Security-Monitor-${v}-linux-amd64.deb`, optional: true },
];

/** 產生 latest.json 的內容（並驗章）。 */
export function buildManifest({ version, dist, repo, pubkey, notes, now = new Date(), allowMissing = false }) {
  const pub = parsePublicKey(pubkey);
  const platforms = {};
  const missing = [];
  for (const t of TARGETS(version)) {
    const file = path.join(dist, t.file);
    const sig = `${file}.sig`;
    if (!fs.existsSync(file) || !fs.existsSync(sig)) {
      if (!t.optional) missing.push(t.file);
      continue;
    }
    try {
      verifySignature(fs.readFileSync(file), fs.readFileSync(sig, 'utf8'), pub);
    } catch (e) {
      throw new Error(`${t.file}: ${e.message}`);
    }
    const entry = { signature: fs.readFileSync(sig, 'utf8').trim(), url: `https://github.com/${repo}/releases/download/v${version}/${t.file}` };
    for (const k of t.keys) platforms[k] = entry;
  }
  if (missing.length && !allowMissing) throw new Error(`missing updater artifacts or signatures: ${missing.join(', ')}`);
  return { version, notes, pub_date: now.toISOString().replace(/\.\d{3}Z$/, 'Z'), platforms };
}

function main() {
  const args = process.argv.slice(2);
  const [version, dist] = args;
  if (!version || !dist) {
    console.error('usage: node scripts/updater-manifest.mjs <version> <dist-dir> [--repo owner/name] [--allow-missing]');
    process.exit(2);
  }
  const ri = args.indexOf('--repo');
  const repo = ri >= 0 ? args[ri + 1] : 'markku636/ai-security-monitor';
  const conf = JSON.parse(fs.readFileSync(path.join(root, 'desktop', 'src-tauri', 'tauri.conf.json'), 'utf8'));
  const pubkey = conf.plugins?.updater?.pubkey;
  if (!pubkey) throw new Error('tauri.conf.json has no plugins.updater.pubkey');
  // 說明放短短的連結就好：App 的提示只顯示版本與「看更新內容」
  const section = changelogSection(version);
  const first = section?.split(/\r?\n/).find((l) => l.trim())?.replace(/\*\*/g, '') ?? '';
  const notes = `${first.slice(0, 400)}${first.length > 400 ? '…' : ''}\n\nhttps://github.com/${repo}/releases/tag/v${version}`.trim();
  const m = buildManifest({ version, dist, repo, pubkey, notes, allowMissing: args.includes('--allow-missing') });
  fs.writeFileSync(path.join(dist, 'latest.json'), `${JSON.stringify(m, null, 2)}\n`);
  console.log(`latest.json: ${version}, ${Object.keys(m.platforms).length} platform keys (${Object.keys(m.platforms).join(', ')}); signatures verified`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    console.error(`updater-manifest: ${e.message}`);
    process.exit(1);
  }
}
