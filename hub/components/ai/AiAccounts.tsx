'use client';

// AI 帳號卡：Hub 主機上的 Claude Code／Codex 有沒有登入、登入誰；在網頁上登入（官方 CLI 的登入流程）或登出。
// Hub 不讀、不存任何 token：Claude 的授權碼直接交給 `claude auth login`，Codex 用裝置碼由 OpenAI 網站完成。
import { useCallback, useEffect, useState } from 'react';
import { Hint } from '@/components/ui/Hint';
import { apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';

type Provider = 'claude' | 'codex';
type LoginState = 'starting' | 'waiting_code' | 'waiting_user' | 'completing' | 'done' | 'error' | 'cancelled' | 'expired';

interface Status {
  installed: boolean;
  loggedIn: boolean;
  method: string | null;
  email: string | null;
  plan: string | null;
  org: string | null;
  envOverride: string[];
  error: string | null;
}
interface Login {
  id: string;
  provider: Provider;
  state: LoginState;
  url: string | null;
  userCode: string | null;
  error: string | null;
  terminalRequired: boolean;
}
interface Row {
  id: Provider;
  status: Status;
  login: Login | null;
}

const NAME: Record<Provider, string> = { claude: 'Claude Code', codex: 'Codex' };
const BTN = 'rounded-md border border-teal-600 px-2.5 py-1 text-xs text-teal-700 hover:bg-teal-50 disabled:opacity-50 dark:text-teal-300 dark:hover:bg-teal-950';
const BTN_SOLID = 'rounded-md bg-teal-700 px-3 py-1 text-sm text-white hover:bg-teal-800 disabled:opacity-50';
const BTN_DANGER = 'rounded-md border border-red-300 px-2.5 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950/40';
const ACTIVE: LoginState[] = ['starting', 'waiting_code', 'waiting_user', 'completing'];
const COMPOSE = 'docker compose -f docker/compose.standalone.yml --env-file .env exec hub';

function Cmd({ value }: { value: string }) {
  const { t } = useT();
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2">
      <code className="flex-1 overflow-x-auto whitespace-nowrap rounded bg-slate-100 px-2 py-1 font-mono text-xs dark:bg-slate-800">{value}</code>
      <button
        type="button"
        className={BTN}
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        {copied ? t('已複製') : t('複製')}
      </button>
    </div>
  );
}

function methodText(t: (s: string) => string, s: Status): string {
  switch (s.method) {
    case 'claude.ai':
      return t('Claude 訂閱帳號');
    case 'chatgpt':
      return t('ChatGPT 帳號');
    case 'api_key':
    case 'api_key_helper':
      return t('API key');
    case 'oauth_token':
      return t('長效 token（環境變數）');
    default:
      return s.method ?? '';
  }
}

export function AiAccounts() {
  const { t } = useT();
  const [rows, setRows] = useState<Row[] | null>(null);
  const [busy, setBusy] = useState<Provider | null>(null);
  const [code, setCode] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/ai/accounts', { credentials: 'same-origin', cache: 'no-store' });
      if (r.ok) setRows(((await r.json()) as { providers: Row[] }).providers);
    } catch {
      // 下次再試
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // 有進行中的登入（Codex 等使用者到 OpenAI 網站輸入代碼）就每 3 秒問一次
  const pending = rows?.find((r) => r.login && ACTIVE.includes(r.login.state));
  useEffect(() => {
    if (!pending) return;
    const timer = setInterval(async () => {
      const r = await fetch(`/api/ai/accounts/${pending.id}/login`, { credentials: 'same-origin', cache: 'no-store' });
      if (!r.ok) return;
      const { login } = (await r.json()) as { login: Login | null };
      if (!login || !ACTIVE.includes(login.state)) await load();
      else setRows((rs) => rs?.map((x) => (x.id === pending.id ? { ...x, login } : x)) ?? rs);
    }, 3000);
    return () => clearInterval(timer);
  }, [pending, load]);

  const errorText = (l: Login): string => {
    switch (l.error) {
      case 'terminal_required':
        return t('這個版本的 CLI 不能在網頁上登入，請用下面「怎麼登入？」裡的指令。');
      case 'device_auth_disabled':
        return t('你的 ChatGPT 帳號還沒開啟「裝置碼登入」：到 ChatGPT 設定 → 安全性開啟後再試一次。');
      case 'expired':
        return t('登入逾時（15 分鐘），請重新開始。');
      case 'timeout':
        return t('送出授權碼後等太久沒有回應，請重新開始。');
      case 'not_installed':
        return t('Hub 主機上沒有安裝這個 CLI。');
      default:
        return t('登入失敗：{e}', { e: l.error ?? '' });
    }
  };

  const start = async (p: Provider) => {
    setBusy(p);
    setMsg(null);
    setCode('');
    const r = await apiPost<{ login?: Login; error?: string }>(`/api/ai/accounts/${p}/login`, {});
    setBusy(null);
    if (!r.ok || !r.data.login) {
      setMsg({ ok: false, text: t('無法開始登入：{e}', { e: r.data.error ?? String(r.status) }) });
      return;
    }
    const login = r.data.login;
    setRows((rs) => rs?.map((x) => (x.id === p ? { ...x, login } : x)) ?? rs);
  };

  const complete = async (p: Provider) => {
    if (!code.trim()) return;
    setBusy(p);
    const r = await apiPost<{ login?: Login; error?: string }>(`/api/ai/accounts/${p}/login/complete`, { code: code.trim() });
    setBusy(null);
    setCode('');
    if (!r.ok || !r.data.login) {
      setMsg({ ok: false, text: t('送出失敗：{e}', { e: r.data.error ?? String(r.status) }) });
      return;
    }
    if (r.data.login.state === 'done') setMsg({ ok: true, text: t('{name} 已登入。', { name: NAME[p] }) });
    await load();
    if (r.data.login.state !== 'done') setRows((rs) => rs?.map((x) => (x.id === p ? { ...x, login: r.data.login ?? null } : x)) ?? rs);
  };

  const cancel = async (p: Provider) => {
    await apiPost(`/api/ai/accounts/${p}/login/cancel`, {});
    await load();
  };

  const signOut = async (p: Provider) => {
    if (!window.confirm(t('登出 Hub 主機上的 {name}？登出後 AI 助手就不能用它，要再登入才行。（不影響你自己電腦上的登入）', { name: NAME[p] }))) return;
    setBusy(p);
    setMsg(null);
    const r = await apiPost<{ ok?: boolean; error?: string; detail?: string }>(`/api/ai/accounts/${p}/logout`, {});
    setBusy(null);
    setMsg(r.ok ? { ok: true, text: t('{name} 已登出。', { name: NAME[p] }) } : { ok: false, text: t('登出失敗：{e}', { e: r.data.detail ?? r.data.error ?? String(r.status) }) });
    await load();
  };

  return (
    <section id="ai-accounts" className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <h2 className="mb-3 text-sm font-semibold text-slate-600 dark:text-slate-300">
        {t('AI 帳號')}
        <Hint text={t('AI 助手用 Hub 主機上的 Claude Code 或 Codex 分析；要先登入其中一個。這裡登入的是 Hub 主機上的程式，不影響你自己電腦上的登入。')} />
      </h2>
      {!rows ? (
        <p className="text-sm text-slate-500">{t('讀取中…')}</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {rows.map(({ id: p, status: s, login: l }) => {
            const active = l && ACTIVE.includes(l.state);
            return (
              <li key={p} className="space-y-2 py-3">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="w-28 font-medium">{NAME[p]}</span>
                  {!s.installed ? (
                    <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300">{t('未安裝')}</span>
                  ) : s.loggedIn ? (
                    <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs text-green-800 dark:bg-green-900/40 dark:text-green-300">{t('已登入')}</span>
                  ) : (
                    <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs text-amber-900 dark:bg-amber-900/40 dark:text-amber-200">{t('未登入')}</span>
                  )}
                  {s.loggedIn ? (
                    <span className="text-xs text-slate-500">
                      {[s.email, methodText(t, s), s.plan ? s.plan.toUpperCase() : null].filter(Boolean).join(' · ')}
                    </span>
                  ) : null}
                  <span className="ml-auto flex gap-2">
                    {s.installed && !active ? (
                      <button type="button" className={BTN} disabled={busy !== null} onClick={() => void start(p)}>
                        {s.loggedIn ? t('重新登入') : t('登入')}
                      </button>
                    ) : null}
                    {s.installed && s.loggedIn && !active ? (
                      <button type="button" className={BTN_DANGER} disabled={busy !== null} onClick={() => void signOut(p)}>
                        {t('登出')}
                      </button>
                    ) : null}
                  </span>
                </div>
                {s.envOverride.length ? (
                  <p className="text-xs text-amber-700 dark:text-amber-400">
                    {t('Hub 設了環境變數 {vars}，CLI 會優先用它；網頁上的登入／登出管不到，要改請改 Hub 的環境變數。', { vars: s.envOverride.join('、') })}
                  </p>
                ) : null}
                {active && l ? (
                  <div className="space-y-2 rounded-lg border border-teal-600/40 bg-teal-50/50 p-3 text-sm dark:bg-teal-950/30">
                    {p === 'claude' ? (
                      <>
                        <p>
                          <b>1.</b> {t('開啟授權頁面，用你的 Claude 帳號登入並按「授權」：')}{' '}
                          {l.url ? (
                            <a className="text-teal-700 underline dark:text-teal-300" href={l.url} target="_blank" rel="noreferrer noopener">
                              {t('開啟 Claude 授權頁面')}
                            </a>
                          ) : (
                            <span className="text-slate-500">{t('準備中…')}</span>
                          )}
                        </p>
                        <p>
                          <b>2.</b> {t('授權後頁面會顯示一組代碼，複製後貼到這裡：')}
                        </p>
                        <div className="flex flex-wrap gap-2">
                          <input
                            className="min-w-64 flex-1 rounded-md border border-slate-300 bg-white px-2 py-1 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                            value={code}
                            onChange={(e) => setCode(e.target.value)}
                            placeholder={t('貼上授權碼')}
                            autoComplete="off"
                            spellCheck={false}
                            disabled={l.state !== 'waiting_code' || busy !== null}
                          />
                          <button type="button" className={BTN_SOLID} disabled={!code.trim() || l.state !== 'waiting_code' || busy !== null} onClick={() => void complete(p)}>
                            {l.state === 'completing' || busy === p ? t('登入中…') : t('完成登入')}
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        <p>
                          <b>1.</b> {t('開啟 OpenAI 的裝置登入頁面（可以用手機或任何電腦）：')}{' '}
                          {l.url ? (
                            <a className="text-teal-700 underline dark:text-teal-300" href={l.url} target="_blank" rel="noreferrer noopener">
                              {l.url}
                            </a>
                          ) : null}
                        </p>
                        <p>
                          <b>2.</b> {t('用你的 ChatGPT 帳號登入，輸入這組代碼（15 分鐘內有效）：')}
                        </p>
                        <div className="font-mono text-2xl font-semibold tracking-widest text-teal-700 dark:text-teal-300">{l.userCode ?? '…'}</div>
                        <p className="text-xs text-slate-500">{t('完成後這裡會自動更新（每 3 秒確認一次）。只輸入你自己在這裡開始的代碼；別人給你的代碼不要輸入。')}</p>
                      </>
                    )}
                    <button type="button" className={BTN} onClick={() => void cancel(p)}>
                      {t('取消登入')}
                    </button>
                  </div>
                ) : null}
                {l && !active && l.state !== 'done' && l.state !== 'cancelled' ? <p className="text-xs text-red-700 dark:text-red-400">{errorText(l)}</p> : null}
              </li>
            );
          })}
        </ul>
      )}
      {msg ? <p className={`mt-2 text-sm ${msg.ok ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'}`}>{msg.text}</p> : null}
      <details className="mt-3 text-sm">
        <summary className="cursor-pointer text-teal-700 dark:text-teal-300">{t('怎麼登入？登出會怎樣？')}</summary>
        <div className="mt-2 space-y-2 text-slate-600 dark:text-slate-300">
          <p>
            <b>Claude Code</b>：{t('按「登入」→ 開啟授權頁面、用你的 Claude（Pro／Max）帳號登入並授權 → 頁面會顯示一組代碼 → 貼回上面的欄位按「完成登入」。')}
          </p>
          <p>
            <b>Codex</b>：{t('按「登入」→ 在任何裝置打開顯示的網址、用 ChatGPT 帳號登入 → 輸入畫面上的代碼 → 這裡會自動顯示已登入。第一次用要先在 ChatGPT 設定 → 安全性開啟「裝置碼登入」。')}
          </p>
          <p>{t('登出：刪除 Hub 主機上 CLI 存的登入資料；AI 助手要再登入才能用。不影響你自己電腦上的 Claude Code／Codex。')}</p>
          <p>{t('Hub 不會讀取或保存任何 token：授權碼直接交給官方程式，登入資料由程式自己存在 Hub 的資料目錄（/data）。只登入你自己的帳號；多人共用或商業用途請改用 API key（Hub 環境變數 ANTHROPIC_API_KEY／OPENAI_API_KEY）。')}</p>
          <p>{t('網頁上的按鈕不能用時，在 Hub 主機上執行（伺服器版把 compose.standalone.yml 換成 compose.yml）：')}</p>
          <Cmd value={`${COMPOSE} claude auth login`} />
          <Cmd value={`${COMPOSE} claude auth logout`} />
          <Cmd value={`${COMPOSE} codex login --device-auth`} />
          <Cmd value={`${COMPOSE} codex logout`} />
          <p className="text-xs text-slate-500">
            {t('詳細說明：')}
            <a className="underline" href="https://github.com/markku636/ai-security-monitor/blob/main/docs/ai-login.md" target="_blank" rel="noreferrer noopener">
              docs/ai-login.md
            </a>
          </p>
        </div>
      </details>
    </section>
  );
}
