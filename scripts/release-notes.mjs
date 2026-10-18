// 產生 GitHub Release 說明：這版重點 → 該下載哪個檔（依這版實際的資產名）→ 各平台怎麼安裝 → 升級 → CHANGELOG。
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
  if (has('latest.json')) {
    const upd = ['latest.json', ...names.filter((n) => n.startsWith(gui('')) && n.endsWith('.app.tar.gz'))];
    rows.push(
      `| 桌面版自動更新用 · used by the desktop app's updater | ${upd.map((n) => `\`${n}\``).join('、')} | 桌面版自己會下載並驗證簽章，**不用手動下載**<br>downloaded and signature-checked by the app itself, **no need to download** |`,
    );
  }
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
    `| **集中看多台主機** · Security Hub | \`ghcr.io/${REPO.split('/')[0]}/ai-security-monitor-hub:${version}\` | Docker 映像（\`-slim\` 不含 AI CLI；\`-commercial\`／\`-noncommercial\` 固定公司用／個人用的情資來源，沒有後綴照網頁設定、預設個人用），見 docs/docker.md<br>Docker image (\`-slim\` without AI CLIs; \`-commercial\` / \`-noncommercial\` fix the intel usage, plain tags follow the web setting, personal use by default) |`,
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

// 0.7.1 起 install.sh 有 --desktop（macOS 用 curl 安裝桌面版，不經過 Gatekeeper）、.app 有 ad-hoc 簽章
const newer = (a, b) => {
  const pa = a.split(/[.-]/).map(Number);
  const pb = b.split(/[.-]/).map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  return true;
};
const macScript = newer(version, '0.7.1');
const raw = (n) => `https://github.com/${REPO}/releases/latest/download/${n}`;

const HOW = [
  '## 怎麼安裝 · How to install',
  '',
  '> 桌面版沒有向 Microsoft／Apple 購買程式碼簽章，第一次打開時系統會警告「無法確認發行者」，照下面的步驟放行即可。所有檔案的 SHA256 都在 `SHA256SUMS`。',
  '> The desktop apps are not code-signed by Microsoft / Apple, so the first launch shows a warning; follow the steps below. SHA256 of every file is in `SHA256SUMS`.',
  '',
  '### Windows 10／11（桌面版）',
  '',
  `1. 下載 \`${gui('windows-x64-setup.exe')}\`，雙擊安裝（裝在目前使用者，不需要系統管理員）。 · Download and double-click; no admin rights needed.`,
  '2. 出現藍色的「Windows 已保護您的電腦」：按「**其他資訊**」→「**仍要執行**」。 · On "Windows protected your PC", click **More info** → **Run anyway**.',
  '3. 裝好後會自動打開；右下角系統匣有 AI Security Monitor 圖示。 · It opens automatically and sits in the system tray.',
  '',
  '### macOS（桌面版）',
  '',
  ...(macScript
    ? [
        '**最簡單（建議）**：打開「終端機」貼上這行，會依你的晶片下載 dmg、比對 SHA256、裝進「應用程式」，**不會被 Gatekeeper 擋**：',
        '**Easiest (recommended)**: paste this into Terminal. It picks the right dmg for your chip, verifies SHA256 and installs into Applications **without the Gatekeeper prompt**:',
        '',
        '```bash',
        `curl -fsSL ${raw('install.sh')} | sh -s -- --desktop`,
        '```',
        '',
        '**手動安裝 · Manual install**',
        '',
      ]
    : []),
  `1. Apple Silicon（M1、M2…）下載 \`${gui('macos-arm64.dmg')}\`，Intel 下載 \`${gui('macos-x64.dmg')}\`（蘋果選單 →「關於這台 Mac」看晶片）。 · Apple Silicon → arm64, Intel → x64.`,
  '2. 打開 dmg，把「AI Security Monitor」拖到「應用程式」。 · Open the dmg and drag the app to Applications.',
  '3. 第一次打開會說「無法打開」或「Apple 無法檢查是否含有惡意軟體」：按「完成」，到「**系統設定 → 隱私權與安全性**」往下捲，按「**強制打開**」，輸入密碼後再按「打開」。macOS 14 以前也可以在「應用程式」裡對它按右鍵 →「打開」。 · First launch is blocked: click Done, then **System Settings → Privacy & Security → Open Anyway** (macOS 14 and earlier: right-click → Open).',
  `4. ${macScript ? '萬一還是顯示「**已損毀，無法打開**」（檔案其實沒壞，是隔離屬性造成的）' : '如果顯示「**已損毀，無法打開**」（這個版本在 Apple Silicon 上會這樣，檔案其實沒壞）'}：在終端機執行下面這行再打開。 · If it says the app **is damaged**, run this in Terminal, then open it again:`,
  '',
  '```bash',
  'xattr -dr com.apple.quarantine "/Applications/AI Security Monitor.app"',
  '```',
  '',
  '### Linux（桌面版）',
  '',
  `- Debian／Ubuntu：\`sudo apt install ./${gui('linux-amd64.deb')}\`，之後從應用程式選單打開。 · then open it from the app menu.`,
  `- 其他發行版（免安裝）· Other distros (portable)：\`chmod +x ${gui('linux-x64.AppImage')} && ./${gui('linux-x64.AppImage')}\``,
  '',
  '### 伺服器、沒有桌面的電腦（命令列版）· Servers and headless machines (command line)',
  '',
  '一行安裝：自動下載對應平台的命令列版、比對 SHA256、加進 PATH。 · One line: downloads the CLI for your platform, verifies SHA256, adds it to PATH.',
  '',
  '```bash',
  '# Linux / macOS',
  `curl -fsSL ${raw('install.sh')} | sh`,
  '# 裝成開機就啟動的系統服務 · as a system service started at boot',
  `curl -fsSL ${raw('install.sh')} | sh -s -- --service system`,
  '```',
  '',
  '```powershell',
  '# Windows / Windows Server（PowerShell；系統服務請用「以系統管理員身分執行」· run as Administrator for a system service）',
  `irm ${raw('install.ps1')} | iex`,
  '```',
  '',
  '裝好後執行 `ai-security-monitor doctor` 檢查環境、`ai-security-monitor scan` 掃一次；`ai-security-monitor service install --yes` 設定登入時自動啟動（伺服器加 `--system`）。',
  'Then run `ai-security-monitor doctor` and `ai-security-monitor scan`; `ai-security-monitor service install --yes` starts it at login (`--system` on servers).',
  '',
  '### 集中看多台主機（Security Hub）',
  '',
  `用 Docker 跑 \`ghcr.io/${REPO.split('/')[0]}/ai-security-monitor-hub:${version}\`，步驟見 [docs/docker.md](https://github.com/${REPO}/blob/v${version}/docs/docker.md)。各台電腦的桌面版在「設定 → 加入 Hub」填 Hub 網址即可。 · Run the Docker image (see docs/docker.md), then join from each desktop app in Settings → Join a Hub.`,
  '',
  '> 裝過舊的「AI Security Agent」桌面版（0.1.x）要先解除安裝，新版不會覆蓋它。 · Uninstall the old "AI Security Agent" desktop app (0.1.x) first.',
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
    HOW,
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
