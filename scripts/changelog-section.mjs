// 印出 CHANGELOG.md 的 `## v<version>` 區段（Release 說明用）。
// 用法：node scripts/changelog-section.mjs <version>
// 也可以 import { changelogSection } 取區段內文（scripts/release-notes.mjs 用）。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** `## v<version>` 區段的內文（不含標題）；找不到回 null。 */
export function changelogSection(version) {
  const lines = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8').split(/\r?\n/);
  const start = lines.findIndex((l) => l.trim() === `## v${version}` || l.startsWith(`## v${version} `));
  if (start < 0) return null;
  let end = lines.findIndex((l, i) => i > start && l.startsWith('## '));
  if (end < 0) end = lines.length;
  return lines.slice(start + 1, end).join('\n').trim();
}

function main() {
  const version = process.argv[2];
  if (!version) {
    console.error('usage: node scripts/changelog-section.mjs <version>');
    process.exit(2);
  }
  const body = changelogSection(version);
  if (body === null) {
    console.error(`CHANGELOG.md has no "## v${version}" section`);
    process.exit(1);
  }
  const install = [
    '',
    '---',
    '',
    '```bash',
    '# Linux / macOS',
    'curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh',
    '```',
    '',
    '```powershell',
    '# Windows',
    'irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex',
    '```',
    '',
    `Security Hub: \`ghcr.io/markku636/ai-security-monitor-hub:${version}\` (\`-slim\` without the AI CLIs; also published as \`ghcr.io/markku636/ai-security-agent-hub\` for the transition) — see docs/docker.md.`,
    'Every binary is listed in SHA256SUMS. `asa-<version>-*` files are identical copies of `ai-security-monitor-<version>-*` so that 0.1.x `asa self-update` keeps working.',
  ].join('\n');
  process.stdout.write(`${body}\n${install}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
