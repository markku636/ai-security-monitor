// 印出 CHANGELOG.md 的 `## v<version>` 區段（Release 說明用）。
// 用法：node scripts/changelog-section.mjs <version>
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const version = process.argv[2];
if (!version) {
  console.error('usage: node scripts/changelog-section.mjs <version>');
  process.exit(2);
}
const lines = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8').split(/\r?\n/);
const start = lines.findIndex((l) => l.trim() === `## v${version}` || l.startsWith(`## v${version} `));
if (start < 0) {
  console.error(`CHANGELOG.md has no "## v${version}" section`);
  process.exit(1);
}
let end = lines.findIndex((l, i) => i > start && l.startsWith('## '));
if (end < 0) end = lines.length;
const body = lines.slice(start + 1, end).join('\n').trim();
const install = [
  '',
  '---',
  '',
  '```bash',
  '# Linux / macOS',
  'curl -fsSL https://github.com/markku636/ai-security-agent/releases/latest/download/install.sh | sh',
  '```',
  '',
  '```powershell',
  '# Windows',
  'irm https://github.com/markku636/ai-security-agent/releases/latest/download/install.ps1 | iex',
  '```',
  '',
  `Security Hub: \`ghcr.io/markku636/ai-security-agent-hub:${version}\` (\`-slim\` without the AI CLIs) — see docs/docker.md.`,
  'Every binary is listed in SHA256SUMS.',
].join('\n');
process.stdout.write(`${body}\n${install}\n`);
