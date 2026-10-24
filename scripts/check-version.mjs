// 發版前檢查：agent（Cargo.toml／lock）、hub（package(-lock).json、env.ts 預設）、桌面版（package(-lock).json、tauri.conf.json、Cargo.toml／lock）、
// docker/Dockerfile 與 .github/workflows/hub-image.yml 的 ASA_HUB_VERSION、docker/Dockerfile.dns 與 docker/Dockerfile.webscan 的 ASA_VERSION
// 都等於 <version>，CHANGELOG 有 `## v<version>`。
// 用法：node scripts/check-version.mjs <version> [--no-changelog]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const [version, ...flags] = process.argv.slice(2);
if (!version || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/.test(version)) {
  console.error('usage: node scripts/check-version.mjs <x.y.z> [--no-changelog]');
  process.exit(2);
}
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const errors = [];

const hub = JSON.parse(read('hub/package.json')).version;
if (hub !== version) errors.push(`hub/package.json is ${hub}`);

const cargo = read('agent/Cargo.toml');
const pkg = /\[package\][\s\S]*?^version\s*=\s*"([^"]+)"/m.exec(cargo)?.[1];
if (pkg !== version) errors.push(`agent/Cargo.toml is ${pkg}`);

const lock = read('agent/Cargo.lock');
const locked = /\[\[package\]\]\r?\nname = "ai-security-monitor"\r?\nversion = "([^"]+)"/.exec(lock)?.[1];
if (locked !== version) {
  errors.push(`agent/Cargo.lock has ai-security-monitor ${locked} (run cargo update -p ai-security-monitor)`);
}

// 桌面版：安裝檔名與 App 版本取自 tauri.conf.json
for (const p of ['desktop/package.json', 'desktop/src-tauri/tauri.conf.json']) {
  const v = JSON.parse(read(p)).version;
  if (v !== version) errors.push(`${p} is ${v}`);
}
for (const p of ['hub/package-lock.json', 'desktop/package-lock.json']) {
  const j = JSON.parse(read(p));
  if (j.version !== version || j.packages?.['']?.version !== version) errors.push(`${p} is ${j.version} (run npm install)`);
}
const dcargo = /\[package\][\s\S]*?^version\s*=\s*"([^"]+)"/m.exec(read('desktop/src-tauri/Cargo.toml'))?.[1];
if (dcargo !== version) errors.push(`desktop/src-tauri/Cargo.toml is ${dcargo}`);
const dlock = read('desktop/src-tauri/Cargo.lock');
for (const name of ['ai-security-monitor', 'ai-security-monitor-desktop']) {
  const v = new RegExp(`\\[\\[package\\]\\]\\r?\\nname = "${name}"\\r?\\nversion = "([^"]+)"`).exec(dlock)?.[1];
  if (v !== version) errors.push(`desktop/src-tauri/Cargo.lock has ${name} ${v}`);
}
// 映像建置寫死的版本號：每一處都要等於 <version>（hub-image.yml 是 main 分支自動推的 Hub 映像）
for (const [p, re, name] of [
  ['docker/Dockerfile', /ARG ASA_HUB_VERSION=(\S+)/g, 'ASA_HUB_VERSION'],
  ['docker/Dockerfile.dns', /ARG ASA_VERSION=(\S+)/g, 'ASA_VERSION'],
  ['docker/Dockerfile.webscan', /ARG ASA_VERSION=(\S+)/g, 'ASA_VERSION'],
  ['.github/workflows/hub-image.yml', /ASA_HUB_VERSION=(\S+)/g, 'ASA_HUB_VERSION'],
]) {
  const found = [...read(p).matchAll(re)].map((m) => m[1]);
  if (!found.length || found.some((v) => v !== version)) errors.push(`${p} ${name} is ${found.join(', ') || 'missing'}`);
}
const envDefault = /npm_package_version \|\| '([^']+)'/.exec(read('hub/lib/env.ts'))?.[1];
if (envDefault !== version) errors.push(`hub/lib/env.ts fallback version is ${envDefault}`);

if (!flags.includes('--no-changelog') && !new RegExp(`^## v${version.replace(/\./g, '\\.')}\\b`, 'm').test(read('CHANGELOG.md'))) {
  errors.push(`CHANGELOG.md has no "## v${version}" section`);
}

if (errors.length) {
  console.error(`version check failed for ${version}:\n  - ${errors.join('\n  - ')}`);
  process.exit(1);
}
console.log(`version ${version} ok`);
