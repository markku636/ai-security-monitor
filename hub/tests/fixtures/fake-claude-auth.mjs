// 測試用的假 `claude auth status|login|logout`：登入狀態存在 CLAUDE_CONFIG_DIR/logged（hub 的 env 白名單有放行這個變數）。
// login 照真的 CLI 印授權網址與「Paste code here if prompted >」，從 stdin 讀一行授權碼：good-code 才成功。
import fs from 'node:fs';
import path from 'node:path';

const [cmd, sub] = process.argv.slice(2);
const dir = process.env.CLAUDE_CONFIG_DIR ?? '.';
const flag = path.join(dir, 'logged');

if (cmd !== 'auth') process.exit(2);
if (sub === 'status') {
  const on = fs.existsSync(flag);
  process.stdout.write(
    JSON.stringify(on ? { loggedIn: true, authMethod: 'claude.ai', email: 'tester@example.com', orgName: 'Test Org', subscriptionType: 'max' } : { loggedIn: false, authMethod: 'none' }),
  );
  process.exit(on ? 0 : 1);
}
if (sub === 'logout') {
  fs.rmSync(flag, { force: true });
  process.stdout.write('Successfully logged out from your Anthropic account.\n');
  process.exit(0);
}
if (sub === 'login') {
  process.stdout.write('Opening browser to sign in…\nIf the browser didn\'t open, visit: https://claude.com/cai/oauth/authorize?code=true&client_id=fake&state=xyz\nPaste code here if prompted > ');
  let buf = '';
  process.stdin.on('data', (d) => {
    buf += d.toString('utf8');
    if (!buf.includes('\n')) return;
    const code = buf.split('\n')[0].trim();
    // 確認 hub 沒把授權碼帶進環境變數或參數
    if (code === 'good-code' && !JSON.stringify(process.argv).includes(code)) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(flag, '1');
      process.stdout.write('\nLogin successful.\n');
      process.exit(0);
    }
    process.stdout.write('\nOAuth error: Invalid code. Please make sure the full code was copied\n');
    process.exit(1);
  });
  setInterval(() => {}, 1000);
} else {
  process.exit(2);
}
