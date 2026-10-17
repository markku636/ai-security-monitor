// 發版前檢查：hub/package.json、agent/Cargo.toml、agent/Cargo.lock 的版本都等於 <version>，CHANGELOG 有 `## v<version>`。
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

if (!flags.includes('--no-changelog') && !new RegExp(`^## v${version.replace(/\./g, '\\.')}\\b`, 'm').test(read('CHANGELOG.md'))) {
  errors.push(`CHANGELOG.md has no "## v${version}" section`);
}

if (errors.length) {
  console.error(`version check failed for ${version}:\n  - ${errors.join('\n  - ')}`);
  process.exit(1);
}
console.log(`version ${version} ok`);
