// 測試用的假 `codex login status|--device-auth`、`codex logout`：狀態存在 CODEX_HOME。
// device-auth 照真的 CLI 印網址與一次性代碼（帶 ANSI 顏色），等測試建立 CODEX_HOME/approve（模擬使用者在 OpenAI 網站輸入完成）。
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const dir = process.env.CODEX_HOME ?? '.';
const logged = path.join(dir, 'auth.json');

if (args[0] === 'logout') {
  const was = fs.existsSync(logged);
  fs.rmSync(logged, { force: true });
  process.stderr.write(was ? 'Successfully logged out\n' : 'Not logged in\n');
  process.exit(0);
}
if (args[0] === 'login' && args[1] === 'status') {
  const on = fs.existsSync(logged);
  process.stderr.write(on ? 'Logged in using ChatGPT\n' : 'Not logged in\n');
  process.exit(on ? 0 : 1);
}
if (args[0] === 'login' && args[1] === '--device-auth') {
  const c = (s) => `\x1b[94m${s}\x1b[0m`;
  process.stdout.write(
    `\nWelcome to Codex [v\x1b[90m0.0.0\x1b[0m]\n\nFollow these steps to sign in with ChatGPT using device code authorization:\n\n1. Open this link in your browser and sign in to your account\n   ${c('https://auth.openai.com/codex/device')}\n\n2. Enter this one-time code \x1b[90m(expires in 15 minutes)\x1b[0m\n   ${c('ABCD-EFGHI')}\n\n`,
  );
  const timer = setInterval(() => {
    if (fs.existsSync(path.join(dir, 'approve'))) {
      clearInterval(timer);
      fs.writeFileSync(logged, '{}');
      process.stderr.write('Successfully logged in\n');
      process.exit(0);
    }
  }, 100);
} else {
  process.exit(2);
}
