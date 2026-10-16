// 在 hub 主機上跑 Claude Code／Codex CLI，掛上 hub 自己的 MCP（/api/mcp，以每輪一次性的 token 認證）。
// 子行程 env 用白名單（絕不把 hub 的金鑰、資料庫網址傳給 AI CLI）；斷線或逾時整棵行程樹收掉。
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { TOOLS } from '@/lib/mcp/tools';
import { claudeEvents, codexEvents, type AiEvent } from './events';

export type Provider = 'claude' | 'codex';
export const PROVIDERS: Provider[] = ['claude', 'codex'];
export const MCP_NAME = 'asahub';

const g = globalThis as unknown as { __asaRunTokens?: Set<string>; __asaAiRunning?: number };

/** 給 /api/mcp 檢查的一次性 token（只在該輪執行期間有效）。 */
export function isRunToken(t: string): boolean {
  return !!g.__asaRunTokens?.has(t);
}

export function running(): number {
  return g.__asaAiRunning ?? 0;
}

export interface Bin {
  command: string;
  /** 指令前置參數（例：node 腳本、cmd /C） */
  prefix: string[];
  path: string;
}

function which(name: string): string | null {
  const exts = process.platform === 'win32' ? ['.exe', '.cmd', '.bat', ''] : [''];
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    for (const ext of exts) {
      const p = path.join(dir, name + ext);
      try {
        if (fs.statSync(p).isFile()) return p;
      } catch {
        // 下一個
      }
    }
  }
  return null;
}

export function resolveBin(p: Provider): Bin | null {
  // 有指定路徑就只用它（指錯就當作沒有，不偷偷改用 PATH 上的另一個）
  const override = process.env[p === 'claude' ? 'ASA_HUB_CLAUDE_BIN' : 'ASA_HUB_CODEX_BIN']?.trim();
  const found = override ? (fs.existsSync(override) ? override : null) : which(p);
  if (!found) return null;
  if (/\.(mjs|cjs|js)$/i.test(found)) return { command: process.execPath, prefix: [found], path: found };
  if (process.platform === 'win32' && /\.(cmd|bat)$/i.test(found)) return { command: 'cmd.exe', prefix: ['/d', '/s', '/c', found], path: found };
  return { command: found, prefix: [], path: found };
}

const ENV_ALLOW = [
  'PATH', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'SystemRoot', 'SYSTEMROOT', 'ComSpec', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL',
  'CLAUDE_CONFIG_DIR', 'CODEX_HOME', 'CLAUDE_CODE_OAUTH_TOKEN', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'CODEX_API_KEY', 'NODE_EXTRA_CA_CERTS',
  'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'USE_BUILTIN_RIPGREP',
];

export function childEnv(extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of ENV_ALLOW) {
    const v = process.env[k];
    if (v !== undefined) env[k] = v;
  }
  return { ...env, ...extra };
}

export function internalUrl(): string {
  return (process.env.ASA_HUB_INTERNAL_URL ?? `http://127.0.0.1:${process.env.PORT ?? 3000}`).replace(/\/$/, '');
}

export interface RunSpec {
  provider: Provider;
  prompt: string;
  system: string;
  maxTurns: number;
  timeoutMs: number;
  model?: string;
}

export function claudeArgs(spec: RunSpec, mcpConfig: string, systemFlag: boolean): string[] {
  const a = ['-p', '--output-format', 'stream-json', '--verbose', '--include-partial-messages', '--permission-mode', 'dontAsk'];
  a.push('--allowedTools', TOOLS.map((t) => `mcp__${MCP_NAME}__${t.name}`).join(','));
  a.push('--mcp-config', mcpConfig, '--strict-mcp-config', '--max-turns', String(Math.max(1, spec.maxTurns)));
  if (spec.model) a.push('--model', spec.model);
  if (systemFlag && spec.system.trim()) a.push('--append-system-prompt', spec.system);
  return a;
}

const tomlStr = (s: string) => (s.includes("'") || /[\r\n]/.test(s) ? JSON.stringify(s) : `'${s}'`);

export function codexArgs(spec: RunSpec, workspace: string, url: string): string[] {
  const a = [
    'exec', '--json', '--skip-git-repo-check', '--sandbox', 'read-only', '--cd', workspace,
    '-c', `mcp_servers.${MCP_NAME}.url=${tomlStr(url)}`,
    '-c', `mcp_servers.${MCP_NAME}.bearer_token_env_var='ASA_HUB_MCP_RUN_TOKEN'`,
    '-c', "approval_policy='never'",
  ];
  if (spec.model) a.push('--model', spec.model);
  a.push('-');
  return a;
}

function killTree(child: ChildProcess): void {
  if (child.exitCode !== null || child.pid === undefined) return;
  if (process.platform === 'win32') {
    spawn('taskkill', ['/T', '/F', '/PID', String(child.pid)], { stdio: 'ignore', windowsHide: true });
  } else {
    try {
      process.kill(-child.pid, 'SIGTERM');
      setTimeout(() => {
        try {
          process.kill(-child.pid!, 'SIGKILL');
        } catch {
          // 已結束
        }
      }, 5000).unref();
    } catch {
      child.kill('SIGKILL');
    }
  }
}

export interface RunResult {
  text: string;
  isError: boolean;
  toolsCalled: number;
  cancelled: boolean;
  stderr: string;
}

/** 執行一輪；每個事件呼叫 onEvent。signal 中止時整棵收掉。 */
export async function runAi(spec: RunSpec, bin: Bin, onEvent: (e: AiEvent) => void, signal?: AbortSignal): Promise<RunResult> {
  const token = crypto.randomBytes(24).toString('hex');
  (g.__asaRunTokens ??= new Set()).add(token);
  g.__asaAiRunning = running() + 1;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asa-hub-ai-'));
  const url = `${internalUrl()}/api/mcp`;
  let args: string[];
  let prompt = spec.prompt;
  const viaCmd = bin.command === 'cmd.exe';
  if (spec.provider === 'claude') {
    const cfg = path.join(dir, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { [MCP_NAME]: { type: 'http', url, headers: { Authorization: `Bearer ${token}` } } } }), { mode: 0o600 });
    args = claudeArgs(spec, cfg, !viaCmd);
    if (viaCmd && spec.system.trim()) prompt = `${spec.system.trim()}\n\n---\n\n${spec.prompt}`;
  } else {
    args = codexArgs(spec, dir, url);
    if (spec.system.trim()) prompt = `${spec.system.trim()}\n\n---\n\n${spec.prompt}`;
  }
  const child = spawn(bin.command, [...bin.prefix, ...args], {
    cwd: dir,
    // Next 的型別把 NODE_ENV 設成必填；白名單 env 刻意不帶它
    env: childEnv({ ASA_HUB_MCP_RUN_TOKEN: token }) as unknown as NodeJS.ProcessEnv,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
    detached: process.platform !== 'win32',
  });
  const result: RunResult = { text: '', isError: false, toolsCalled: 0, cancelled: false, stderr: '' };
  const started = Date.now();
  const st = { streamed: false, lastText: undefined as string | undefined };
  let done = false;
  const onAbort = () => {
    result.cancelled = true;
    killTree(child);
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => {
    result.isError = true;
    result.stderr += '\n[timeout]';
    killTree(child);
  }, spec.timeoutMs);
  child.stderr?.on('data', (d: Buffer) => {
    if (result.stderr.length < 64 * 1024) result.stderr += d.toString('utf8');
  });
  child.stdin?.end(prompt);
  const rl = readline.createInterface({ input: child.stdout! });
  rl.on('line', (line) => {
    const evs = spec.provider === 'claude' ? claudeEvents(line, st) : codexEvents(line, st, Date.now() - started);
    for (const e of evs) {
      if (e.type === 'text') result.text += e.text;
      if (e.type === 'tool') result.toolsCalled += 1;
      if (e.type === 'done') {
        done = true;
        result.isError = result.isError || e.is_error;
        if (!result.text.trim() && e.text) result.text = e.text;
      }
      onEvent(e);
    }
  });
  const code: number | null = await new Promise((resolve) => child.on('close', (c) => resolve(c)));
  clearTimeout(timer);
  signal?.removeEventListener('abort', onAbort);
  g.__asaRunTokens?.delete(token);
  g.__asaAiRunning = Math.max(0, running() - 1);
  fs.rmSync(dir, { recursive: true, force: true });
  if (!done && !result.cancelled && code !== 0) result.isError = true;
  return result;
}

export const SYSTEM_PROMPT = (lang: 'zh-TW' | 'en') => `You are a defensive security analyst for the operator of this Security Hub. Use the asahub MCP tools to look at the fleet (agents, findings, connections, threat-intel hits, traffic, crashes, security events). All tools are read-only.
- Look before you conclude; prefer a few targeted calls.
- When you mention a threat-intel hit, cite the vendor, feed and source_url. Never invent sources.
- Separate facts from interpretation; say "unknown" when the data does not support a conclusion.
- Give concrete next steps ordered by urgency (the operator can approve block actions on the Actions page; you cannot change anything).
- Keep it short: verdict first, then evidence, then steps.
Answer in ${lang === 'en' ? 'English' : 'Traditional Chinese (繁體中文, Taiwan usage)'}.`;

export const SCOPE_PROMPTS: Record<string, { zh: string; en: string }> = {
  fleet: { zh: '整體來看，這個車隊目前最需要處理的資安問題是什麼？依急迫程度排序。', en: 'Across the fleet, what are the most urgent security problems right now? Rank them.' },
  traffic: { zh: '解讀車隊的網路流量：哪些目的地或行程可疑？哪些看起來正常？', en: 'Interpret the fleet traffic: which destinations or processes look suspicious, which look normal?' },
  events: { zh: '分析各主機的當機原因（藍屏代碼、模組、時間模式），並評估資安事件是否需要處理。', en: 'Analyze crash root causes on each host (bugcheck codes, modules, timing patterns) and assess whether the security events need action.' },
  agent: { zh: '檢查這台主機（agent_id 見下方）：連線、發現、當機與資安事件，給出結論與處置。', en: 'Review this host (agent_id below): connections, findings, crashes and security events; give a verdict and next steps.' },
};
