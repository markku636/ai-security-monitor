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
import { readEnv } from '@/lib/env';

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
  return (readEnv('ASA_HUB_INTERNAL_URL') || `http://127.0.0.1:${process.env.PORT ?? 3000}`).replace(/\/$/, '');
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

export function killTree(child: ChildProcess): void {
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

export const SYSTEM_PROMPT = (lang: 'zh-TW' | 'en') => `You are a defensive security analyst for the operator of this Security Hub. Use the asahub MCP tools to look at the fleet (agents, findings, connections, threat-intel hits, traffic destinations and traffic volume, performance metrics where hosts enabled them, crashes, security events). All tools are read-only.
- Look before you conclude; prefer a few targeted calls. For counts and breakdowns (per verdict, direction, program, country, port, remote IP, host) call connection_stats instead of counting yourself; you have no shell.
- When you mention a threat-intel hit, cite the vendor, feed and source_url. Never invent sources.
- Separate facts from interpretation; say "unknown" when the data does not support a conclusion.
- You cannot change anything; the operator can approve block actions on the Block approvals page.
How to write (the reader manages these computers but is not a security expert):
- Start with one plain sentence that answers "do I need to worry?" (e.g. "Nothing urgent across the 5 hosts." / "One host needs attention today.").
- Then three short parts with simple headings: What we found, Why it matters, What to do. Skip a part only if it would be empty.
- Short sentences, everyday words. The first time a technical term is unavoidable (C2, ASN, CVE, beacon, DNS tunnel…), explain it in a few words in brackets.
- Say what it means in practice and how sure you are ("very likely", "possibly", "can't tell"); avoid alarming wording.
- Don't paste long lists of IPs or raw data; name the few that matter and summarise the rest.
- What to do = a numbered list, most urgent first, each with where to click in the Hub (or the command on the host) and when (now / this week / when convenient). If nothing needs doing, say so.
- Keep it to about one screen.
Answer in ${lang === 'en' ? 'English' : 'Traditional Chinese (繁體中文, Taiwan usage)'}.`;

export const SCOPE_PROMPTS: Record<string, { zh: string; en: string }> = {
  fleet: { zh: '整體來看，所有主機目前最需要處理的資安問題是什麼？依急迫程度排序。', en: 'Across all hosts, what are the most urgent security problems right now? Rank them.' },
  connections: {
    zh: '分析目前判定為可疑或危險的連線：依目的地／行程分組，說明每一組為什麼被判可疑（情資命中還是行為判斷）、對方可能是什麼服務（用 lookup_indicator 查 IP 的國家／ASN／情資）、哪些可能是誤報、哪些真的需要處理，最後給出處置（需要的話建議封鎖，操作者可在「封鎖審核」核准）。',
    en: 'Analyze the connections currently rated suspicious or dangerous: group them by destination/process, explain why each group was flagged (intel hit or behavior), what the remote service probably is (use lookup_indicator for country/ASN/intel), which are likely false positives and which need action, then give next steps (suggest blocks if needed; the operator approves them on Block approvals).',
  },
  indicator: {
    zh: '分析這個 IP（見下方）：用 lookup_indicator 查它的情資命中（附來源）、國家／ASN、哪些主機的哪個程式連過、連線狀態與次數；判斷它大概是什麼服務（CDN、雲端、廣告、更新伺服器、掃描器、C2…），被判可疑的理由是情資還是行為判斷、是不是誤報，最後給出建議（放著、加白名單、或建議封鎖）。',
    en: 'Analyze this IP (below): use lookup_indicator for its intel hits (with sources), country/ASN, which hosts and processes connected to it, connection states and counts; work out what service it probably is (CDN, cloud, ads, update server, scanner, C2, …), whether the suspicious rating comes from intel or behavior and whether it is a false positive, then recommend what to do (leave it, allowlist it, or suggest a block).',
  },
  ips: {
    zh: '分析下方這幾個 IP（附有 hub 已有的資料：連線紀錄、黑名單命中、人工備註、快取的外部情資）：逐一說明它大概是什麼服務（CDN、雲端、廣告、更新伺服器、掃描器、C2…）、被判可疑的理由是情資還是行為判斷、是不是誤報；再看它們之間有沒有關聯（同一個 ASN／國家、同一個程式、同時間出現）。最後依急迫程度排序，給出每個 IP 的建議（放著、加白名單、或建議封鎖）。',
    en: 'Analyze the IPs below (the hub data on each is attached: connection records, blocklist hits, operator notes, cached external intel): for each, work out what service it probably is (CDN, cloud, ads, update server, scanner, C2, …), whether the suspicious rating comes from intel or behavior and whether it is a false positive; then look for links between them (same ASN/country, same process, appearing at the same time). Finally rank them by urgency and recommend what to do with each (leave it, allowlist it, or suggest a block).',
  },
  traffic: {
    zh: '解讀網路流量：哪些目的地或行程可疑？哪些看起來正常？也用 fleet_traffic 看各主機與各程式的上傳／下載量，找出異常的大量上傳、流量突增或在非上班時間傳很多資料的主機。',
    en: 'Interpret the traffic: which destinations or processes look suspicious, which look normal? Also use fleet_traffic to check upload/download volume per host and per process and point out unusual large uploads, spikes, or hosts moving a lot of data off-hours.',
  },
  dns: {
    zh: '解讀 DNS 監看：先用 dns_overview 看查詢量、熱門網域、新出現的網域與未處理的 DNS 告警；對可疑的網域用 domain_summary 與 lookup_indicator 看是哪些主機、哪個程式查的、解析到哪些 IP、情資有沒有列名（附來源）。分辨誤報（CDN、更新、遙測的亂數子網域）與真的要處理的（情資網域、DNS 通道、DGA、程式自己走加密 DNS），依急迫程度給出處置。',
    en: 'Interpret DNS monitoring: start with dns_overview (lookup volume, top domains, newly seen domains, open DNS findings); for suspicious domains use domain_summary and lookup_indicator to see which hosts and processes looked them up, which IPs they resolved to and whether threat intel lists them (cite sources). Separate false positives (random subdomains of CDNs, updaters, telemetry) from real problems (intel-listed domains, DNS tunneling, DGA, programs using their own encrypted DNS) and give next steps by urgency.',
  },
  domain: {
    zh: '分析這個網域（見下方）：用 domain_summary 看哪些主機的哪個程式查過、結果、解析到的 IP、第一次出現時間與相關告警；用 lookup_indicator 查情資命中（附來源）。判斷它大概是什麼服務、是不是誤報，最後給出建議（放著、加白名單、或在防護 DNS 封鎖）。',
    en: 'Analyze this domain (below): use domain_summary for which hosts and processes looked it up, result codes, resolved IPs, first seen and related findings; use lookup_indicator for threat-intel hits (cite sources). Work out what service it probably is and whether it is a false positive, then recommend what to do (leave it, allowlist it, or block it on the protective DNS).',
  },
  events: { zh: '分析各主機的當機原因（藍屏代碼、模組、時間模式），並評估資安事件是否需要處理。', en: 'Analyze crash root causes on each host (bugcheck codes, modules, timing patterns) and assess whether the security events need action.' },
  agent: { zh: '檢查這台主機（agent_id 見下方）：連線、發現、當機與資安事件，給出結論與處置。', en: 'Review this host (agent_id below): connections, findings, crashes and security events; give a verdict and next steps.' },
};
