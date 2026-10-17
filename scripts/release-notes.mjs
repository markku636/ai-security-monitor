// 產生 GitHub Release 說明：這版重點 → 該下載哪個檔（依這版實際的資產名）→ 一行安裝 → 升級 → CHANGELOG。
// 用法：
//   node scripts/release-notes.mjs <version> <資產目錄>          # release.yml：dist/ 裡的檔案
//   node scripts/release-notes.mjs <version> --names <檔名清單>   # 每行一個檔名（例如 gh release view 的資產）
//   加 --table-only 只印「下載哪一個？」表格
import fs from 'node:fs';
import { changelogSection } from './changelog-section.mjs';

const REPO = 'markku636/ai-security-monitor';
const args = process.argv.slice(2);
const version = args[0];
if (!version || args.length < 2) {
  console.error('usage: node scripts/release-notes.mjs <version> (<dist-dir> | --names <file>) [--table-only]');
  process.exit(2);
}
const tableOnly = args.includes('--table-only');
const ni = args.indexOf('--names');
const names = (
  ni >= 0
    ? fs.readFileSync(args[ni + 1], 'utf8').split(/\r?\n/)
    : fs.readdirSync(args[1], { withFileTypes: true }).filter((d) => d.isFile()).map((d) => d.name)
)
  .map((s) => s.trim())
  .filter(Boolean)
  .sort();

const url = (n) => `https://github.com/${REPO}/releases/download/v${version}/${n}`;
const link = (n) => `[\`${n}\`](${url(n)})`;
const has = (n) => names.includes(n);
const gui = (suffix) => `AI-Security-Monitor-${version}-${suffix}`;
const cli = (suffix) => `ai-security-monitor-${version}-${suffix}`;

const CLI_PLATFORMS = [
  ['windows-x64.exe', 'Windows x64'],
  ['windows-arm64.exe', 'Windows ARM64'],
  ['linux-x64', 'Linux x64'],
  ['linux-arm64', 'Linux ARM64'],
  ['macos-arm64', 'macOS Apple Silicon'],
  ['macos-x64', 'macOS Intel'],
];

function table() {
  const rows = [];
  const guiRow = (suffix, who, how) => {
    if (has(gui(suffix))) rows.push(`| ${who} | ${link(gui(suffix))} | ${how} |`);
  };
  guiRow('windows-x64-setup.exe', '**Windows 10／11，要視窗介面**<br>Windows desktop app', '桌面版安裝檔，雙擊安裝<br>desktop installer, double-click');
  guiRow('macos-arm64.dmg', '**macOS Apple Silicon（M1 以後）**<br>macOS desktop app (Apple Silicon)', '打開後拖到「應用程式」<br>open, drag to Applications');
  guiRow('macos-x64.dmg', '**macOS Intel**<br>macOS desktop app (Intel)', '同上 · same as above');
  guiRow('linux-x64.AppImage', '**Linux 桌面（各發行版）**<br>Linux desktop app (any distro)', '免安裝：`chmod +x` 後執行<br>portable: `chmod +x`, then run');
  guiRow('linux-amd64.deb', '**Debian／Ubuntu 桌面**<br>Debian / Ubuntu desktop app', '`sudo apt install ./檔名.deb`');
  const cliFiles = CLI_PLATFORMS.filter(([s]) => has(cli(s)));
  if (cliFiles.length) {
    rows.push(
      `| **伺服器（含 Windows Server／Server Core）、自動化、沒有桌面**<br>Servers, automation, headless (command-line) | 建議用下方「一行安裝」<br>use the one-line install below<br>或直接下載 · or download: ${cliFiles
        .map(([s, label]) => `[${label}](${url(cli(s))})`)
        .join('、')} | 命令列版：在終端機執行，**不要雙擊**<br>command-line tool: run it in a terminal, don't double-click |`,
    );
  }
  if (has('install.sh') || has('install.ps1')) {
    rows.push(
      `| 一行安裝腳本 · install scripts | ${['install.sh', 'install.ps1'].filter(has).map(link).join('、')} | 下載命令列版、比對 SHA256、可設定開機自動啟動<br>downloads the CLI, verifies SHA256, optional autostart |`,
    );
  }
  rows.push(
    `| **集中看多台主機** · Security Hub | \`ghcr.io/${REPO.split('/')[0]}/ai-security-monitor-hub:${version}\` | Docker 映像（\`-slim\` 不含 AI CLI），見 docs/docker.md<br>Docker image (\`-slim\` without AI CLIs) |`,
  );
  const asa = names.filter((n) => n.startsWith(`asa-${version}-`));
  if (asa.length) {
    rows.push(
      `| 0.1.x 的 \`asa self-update\` 專用 · for 0.1.x self-update only | \`asa-${version}-*\`（${asa.length} 個 · files） | 內容與命令列版相同，**請忽略**<br>identical copies of the CLI, **ignore them** |`,
    );
  }
  if (has('SHA256SUMS')) rows.push(`| 校驗碼 · checksums | ${link('SHA256SUMS')} | 所有檔案的 SHA256 · SHA256 of every file |`);
  return [
    '## 下載哪一個？ · Which file do I need?',
    '',
    '| 你的情況 · Situation | 下載 · Download | 說明 · Notes |',
    '|---|---|---|',
    ...rows,
  ].join('\n');
}

const UNSIGNED = [
  '桌面版安裝檔沒有程式碼簽章 · The desktop installers are not code-signed:',
  '- **Windows**：SmartScreen 出現「Windows 已保護您的電腦」時，按「其他資訊」→「仍要執行」。 · Click "More info" → "Run anyway".',
  '- **macOS**：第一次在「應用程式」裡對 AI Security Monitor 按右鍵 →「打開」→「打開」；或 `xattr -dr com.apple.quarantine "/Applications/AI Security Monitor.app"`。 · Right-click → Open the first time.',
  '- **Linux**：AppImage 先 `chmod +x`；deb 用 `sudo apt install ./AI-Security-Monitor-*.deb`。',
  '- 裝過舊的「AI Security Agent」桌面版（0.1.x）要先解除安裝，新版不會覆蓋它。 · Uninstall the old "AI Security Agent" desktop app first.',
].join('\n');

const INSTALL = [
  '## 一行安裝（命令列版）· One-line install (command line)',
  '',
  '```bash',
  '# Linux / macOS',
  `curl -fsSL https://github.com/${REPO}/releases/latest/download/install.sh | sh`,
  '```',
  '',
  '```powershell',
  '# Windows / Windows Server（PowerShell）',
  `irm https://github.com/${REPO}/releases/latest/download/install.ps1 | iex`,
  '```',
  '',
  '裝好後執行 `ai-security-monitor version` 確認；`ai-security-monitor service install --yes` 設定登入時自動啟動（伺服器加 `--system`）。',
  'Check with `ai-security-monitor version`; `ai-security-monitor service install --yes` starts it at login (`--system` on servers).',
].join('\n');

const UPGRADE = [
  '## 升級 · Upgrading',
  '',
  '- **從 0.2.x**：`ai-security-monitor self-update`（或重跑上面的安裝指令）；桌面版直接安裝新版。 · From 0.2.x: `ai-security-monitor self-update`; install the new desktop app over the old one.',
  '- **從 0.1.x（asa）**：`asa self-update` 升上來後，執行 `ai-security-monitor service install --yes`（系統服務加 `--system`）換掉舊服務，設定目錄會在這時搬到 `ai-security-monitor`；舊設定、Hub 註冊與金鑰都沿用。 · From 0.1.x: `asa self-update`, then `ai-security-monitor service install --yes` to replace the old service; settings, Hub enrollment and keys carry over.',
].join('\n');

const section = changelogSection(version);
let highlights = '';
let changes = section ?? `（CHANGELOG.md 沒有 v${version} 區段 · no CHANGELOG section）`;
if (section) {
  // 第一段（粗體摘要）當「這版重點」，其餘是完整變更
  const [first, ...rest] = section.split(/\r?\n\s*\r?\n/);
  highlights = first.trim();
  changes = rest.join('\n\n').trim();
}

if (tableOnly) {
  process.stdout.write(`${table()}\n`);
} else {
  const out = [
    ...(highlights ? ['## 這版重點 · Highlights', '', highlights, ''] : []),
    table(),
    '',
    UNSIGNED,
    '',
    INSTALL,
    '',
    UPGRADE,
    '',
    '## 變更內容 · Changes',
    '',
    changes,
    '',
  ];
  process.stdout.write(`${out.join('\n')}\n`);
}
