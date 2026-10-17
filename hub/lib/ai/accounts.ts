// AI 帳號：在 hub 主機上查詢／登入／登出 Claude Code 與 Codex CLI（官方程式本身的登入流程）。
// 原則：Hub 不讀、不存任何 token 或授權碼——Claude 的授權碼只是轉寫進官方 `claude auth login` 的 stdin，
// 憑證由 CLI 自己寫進 CLAUDE_CONFIG_DIR／CODEX_HOME；授權碼不寫 log、不進稽核。
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import { childEnv, killTree, resolveBin, type Provider } from './run';

const STATUS_TIMEOUT_MS = 15_000;
const START_WAIT_MS = 20_000;
const COMPLETE_WAIT_MS = 60_000;
const SESSION_TTL_MS = 15 * 60_000;
const OUTPUT_CAP = 16 * 1024;

/** 這些環境變數有設時，CLI 會優先用它們（網頁登入／登出管不到）。 */
const ENV_OVERRIDES: Record<Provider, string[]> = {
  claude: ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN'],
  codex: ['OPENAI_API_KEY', 'CODEX_API_KEY'],
};

export interface AccountStatus {
  installed: boolean;
  loggedIn: boolean;
  /** claude：claude.ai／api_key／oauth_token…；codex：chatgpt／api_key */
  method: string | null;
  email: string | null;
  plan: string | null;
  org: string | null;
  /** 有設、會蓋過登入狀態的環境變數名稱（只給名稱，不給值） */
  envOverride: string[];
  error: string | null;
}

export type LoginState = 'starting' | 'waiting_code' | 'waiting_user' | 'completing' | 'done' | 'error' | 'cancelled' | 'expired';

export interface LoginView {
  id: string;
  provider: Provider;
  state: LoginState;
  /** 要使用者在瀏覽器打開的網址 */
  url: string | null;
  /** Codex 裝置碼（要使用者在 OpenAI 網站輸入；不是憑證） */
  userCode: string | null;
  error: string | null;
  /** CLI 不能在沒有終端機的情況登入 → 請改用指令 */
  terminalRequired: boolean;
  startedAt: string;
  expiresAt: string;
}

interface Session extends LoginView {
  child: ChildProcess;
  output: string;
  actor: string;
  timer: NodeJS.Timeout;
  onFinish?: (s: LoginView) => void;
}

const g = globalThis as unknown as { __asaAiLogin?: Map<Provider, Session> };
const sessions = (): Map<Provider, Session> => (g.__asaAiLogin ??= new Map());

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
export const stripAnsi = (s: string): string => s.replace(ANSI, '');

function envOverride(p: Provider): string[] {
  return ENV_OVERRIDES[p].filter((k) => (process.env[k] ?? '').trim() !== '');
}

function run(p: Provider, args: string[], timeoutMs: number): Promise<{ code: number | null; out: string; err: string }> {
  const bin = resolveBin(p);
  if (!bin) return Promise.resolve({ code: null, out: '', err: 'not installed' });
  return new Promise((resolve) => {
    const child = spawn(bin.command, [...bin.prefix, ...args], {
      env: childEnv() as unknown as NodeJS.ProcessEnv,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      detached: process.platform !== 'win32',
    });
    let out = '';
    let err = '';
    child.stdout?.on('data', (d: Buffer) => {
      if (out.length < OUTPUT_CAP) out += d.toString('utf8');
    });
    child.stderr?.on('data', (d: Buffer) => {
      if (err.length < OUTPUT_CAP) err += d.toString('utf8');
    });
    const timer = setTimeout(() => killTree(child), timeoutMs);
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ code: null, out, err: err || e.message });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, out: stripAnsi(out), err: stripAnsi(err) });
    });
  });
}

const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);

/** 目前的登入狀態（claude：`auth status --json`；codex：`login status` 的文字＋結束碼）。 */
export async function accountStatus(p: Provider): Promise<AccountStatus> {
  const base: AccountStatus = { installed: !!resolveBin(p), loggedIn: false, method: null, email: null, plan: null, org: null, envOverride: envOverride(p), error: null };
  if (!base.installed) return base;
  if (p === 'claude') {
    const r = await run(p, ['auth', 'status', '--json'], STATUS_TIMEOUT_MS);
    try {
      const j = JSON.parse(r.out.slice(r.out.indexOf('{'))) as Record<string, unknown>;
      return {
        ...base,
        loggedIn: j.loggedIn === true,
        method: str(j.authMethod),
        email: str(j.email),
        plan: str(j.subscriptionType),
        org: str(j.orgName),
      };
    } catch {
      return { ...base, error: (r.err || r.out).trim().split('\n').slice(-1)[0]?.slice(0, 200) || 'status failed' };
    }
  }
  const r = await run(p, ['login', 'status'], STATUS_TIMEOUT_MS);
  const text = `${r.out}\n${r.err}`;
  const loggedIn = r.code === 0 && /logged in/i.test(text) && !/not logged in/i.test(text);
  return {
    ...base,
    loggedIn,
    method: loggedIn ? (/api key/i.test(text) ? 'api_key' : /chatgpt/i.test(text) ? 'chatgpt' : 'unknown') : null,
    error: r.code === null ? (r.err || 'status failed').slice(0, 200) : null,
  };
}

function view(s: Session): LoginView {
  const { id, provider, state, url, userCode, error, terminalRequired, startedAt, expiresAt } = s;
  return { id, provider, state, url, userCode, error, terminalRequired, startedAt, expiresAt };
}

export function loginView(p: Provider): LoginView | null {
  const s = sessions().get(p);
  return s ? view(s) : null;
}

const ACTIVE: LoginState[] = ['starting', 'waiting_code', 'waiting_user', 'completing'];

function finish(s: Session, state: LoginState, error: string | null = null): void {
  if (!ACTIVE.includes(s.state)) return;
  s.state = state;
  s.error = error;
  clearTimeout(s.timer);
  killTree(s.child);
  s.onFinish?.(view(s));
}

/** 從 CLI 輸出擷取網址／裝置碼與狀態。 */
function parseOutput(s: Session): void {
  const text = stripAnsi(s.output);
  if (/raw mode is not supported/i.test(text)) {
    s.terminalRequired = true;
    finish(s, 'error', 'terminal_required');
    return;
  }
  if (s.provider === 'claude') {
    const m = /https:\/\/\S*oauth\/authorize\S*/.exec(text);
    if (m && !s.url) {
      s.url = m[0];
      if (s.state === 'starting') s.state = 'waiting_code';
    }
    return;
  }
  if (/device code login is not enabled/i.test(text)) {
    finish(s, 'error', 'device_auth_disabled');
    return;
  }
  const u = /https:\/\/auth\.openai\.com\/\S*/.exec(text);
  if (u && !s.url) s.url = u[0];
  const after = text.slice(text.search(/one-time code/i) >= 0 ? text.search(/one-time code/i) : text.length);
  const c = /\b([A-Z0-9]{4}-[A-Z0-9]{4,6})\b/.exec(after);
  if (c && !s.userCode) s.userCode = c[1];
  if (s.url && s.userCode && s.state === 'starting') s.state = 'waiting_user';
}

/**
 * 開始登入：Claude 跑 `claude auth login --claudeai`（印出授權網址、從 stdin 讀授權碼），
 * Codex 跑 `codex login --device-auth`（印出網址＋一次性代碼，自己等使用者完成）。
 * 已有進行中的登入就先取消。等到拿到網址（或出錯、逾時）才回傳。
 */
export async function startLogin(p: Provider, actor: string, onFinish?: (v: LoginView) => void): Promise<LoginView> {
  cancelLogin(p);
  const bin = resolveBin(p);
  const now = Date.now();
  const id = `login_${crypto.randomBytes(6).toString('hex')}`;
  if (!bin) {
    return { id, provider: p, state: 'error', url: null, userCode: null, error: 'not_installed', terminalRequired: false, startedAt: new Date(now).toISOString(), expiresAt: new Date(now).toISOString() };
  }
  const args = p === 'claude' ? ['auth', 'login', '--claudeai'] : ['login', '--device-auth'];
  const child = spawn(bin.command, [...bin.prefix, ...args], {
    env: childEnv() as unknown as NodeJS.ProcessEnv,
    stdio: [p === 'claude' ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    windowsHide: true,
    detached: process.platform !== 'win32',
  });
  const s: Session = {
    id,
    provider: p,
    state: 'starting',
    url: null,
    userCode: null,
    error: null,
    terminalRequired: false,
    startedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
    child,
    output: '',
    actor,
    timer: setTimeout(() => finish(s, 'expired', 'expired'), SESSION_TTL_MS),
    onFinish,
  };
  s.timer.unref?.();
  sessions().set(p, s);
  const onData = (d: Buffer) => {
    if (s.output.length < OUTPUT_CAP) s.output += d.toString('utf8');
    parseOutput(s);
  };
  child.stdout?.on('data', onData);
  child.stderr?.on('data', onData);
  child.on('error', (e) => finish(s, 'error', e.message.slice(0, 200)));
  child.on('close', (code) => {
    if (!ACTIVE.includes(s.state)) return;
    if (code === 0) finish(s, 'done');
    else finish(s, 'error', lastLine(s.output) || `exit ${code}`);
  });
  await waitFor(() => s.state !== 'starting', START_WAIT_MS);
  if (s.state === 'starting') finish(s, 'error', lastLine(s.output) || 'no_login_url');
  return view(s);
}

function lastLine(out: string): string {
  const lines = stripAnsi(out)
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !/https?:\/\//.test(l));
  return (lines.at(-1) ?? '').slice(0, 200);
}

async function waitFor(cond: () => boolean, ms: number): Promise<void> {
  const until = Date.now() + ms;
  while (!cond() && Date.now() < until) await new Promise((r) => setTimeout(r, 100));
}

/** Claude：把使用者從瀏覽器複製的授權碼交給 CLI（只寫進 stdin，不保存）。 */
export async function completeLogin(p: Provider, code: string): Promise<{ ok: true; login: LoginView } | { ok: false; error: string }> {
  const s = sessions().get(p);
  if (!s || p !== 'claude') return { ok: false, error: 'no_session' };
  if (s.state !== 'waiting_code') return { ok: false, error: 'bad_state' };
  const c = code.trim();
  if (!c || c.length > 1024 || /[\r\n]/.test(c)) return { ok: false, error: 'bad_code' };
  s.state = 'completing';
  s.child.stdin?.write(`${c}\n`);
  await waitFor(() => s.state !== 'completing', COMPLETE_WAIT_MS);
  if (s.state === 'completing') finish(s, 'error', 'timeout');
  return { ok: true, login: view(s) };
}

export function cancelLogin(p: Provider): boolean {
  const s = sessions().get(p);
  if (!s) return false;
  finish(s, 'cancelled');
  sessions().delete(p);
  return true;
}

/** 登出（`claude auth logout`／`codex logout`）。環境變數設的金鑰清不掉，回傳裡會列出。 */
export async function logout(p: Provider): Promise<{ ok: boolean; error: string | null }> {
  cancelLogin(p);
  if (!resolveBin(p)) return { ok: false, error: 'not_installed' };
  const r = await run(p, p === 'claude' ? ['auth', 'logout'] : ['logout'], STATUS_TIMEOUT_MS);
  return r.code === 0 ? { ok: true, error: null } : { ok: false, error: lastLine(`${r.out}\n${r.err}`) || `exit ${r.code}` };
}

export function resetAccountsForTests(): void {
  for (const p of [...sessions().keys()]) cancelLogin(p);
}
