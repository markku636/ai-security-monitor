'use client';

// 「設定與金鑰 → 通知」：頻道（Email／Slack／Discord／Teams／webhook／syslog）、規則（什麼事送到哪）、最近送出紀錄。
import { useRouter } from 'next/navigation';
import { useState, useTransition, type ReactNode } from 'react';
import { Hint } from '@/components/ui/Hint';
import { apiPost } from '@/lib/api-client';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { useT } from '@/lib/i18n/client';
import type { NotifyView } from '@/lib/notify/admin';

const INPUT = 'w-full rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900';
const BTN = 'whitespace-nowrap rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const SMALL = 'whitespace-nowrap rounded-md border border-slate-300 px-2 py-0.5 text-xs hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:hover:bg-slate-800';
const DANGER = 'whitespace-nowrap rounded-md border border-red-300 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950/40';
const BOX = 'rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900';

type Kind = 'email' | 'slack' | 'discord' | 'teams' | 'webhook' | 'syslog';
const KINDS: Kind[] = ['email', 'slack', 'discord', 'teams', 'webhook', 'syslog'];
const EVENTS = ['finding', 'dangerous_connection', 'host_offline', 'host_joined', 'action_pending', 'daily_digest'] as const;
type Event = (typeof EVENTS)[number];
const SEVS = ['critical', 'high', 'medium', 'low', 'info'] as const;

function kindLabel(t: TFn, k: string): string {
  return ({ email: 'Email', slack: 'Slack', discord: 'Discord', teams: 'Microsoft Teams', webhook: t('Webhook（自訂）'), syslog: 'Syslog' } as Record<string, string>)[k] ?? k;
}

function eventLabel(t: TFn, e: string): string {
  return (
    {
      finding: t('新的問題'),
      dangerous_connection: t('新的危險連線'),
      host_offline: t('主機沒有回報'),
      host_joined: t('新主機加入'),
      action_pending: t('封鎖等待審核'),
      daily_digest: t('每日摘要'),
    } as Record<string, string>
  )[e] ?? e;
}

function eventHint(t: TFn, e: Event): string {
  return {
    finding: t('掃描找到新的問題，而且嚴重度達到你選的門檻（同一個問題只通知一次）。'),
    dangerous_connection: t('有主機連到（或被連自）判定危險的位址，例如威脅情資列名的 IP。'),
    host_offline: t('主機超過設定的分鐘數沒有回報（可能關機、斷網，或 agent 被停掉）。'),
    host_joined: t('有新的電腦加入這個 Hub。'),
    action_pending: t('有封鎖 IP／關閉 port 的動作等你核准。'),
    daily_digest: t('每天固定時間（UTC）送一則：待處理問題數、新增問題、沒回報的主機、等待審核的封鎖。'),
  }[e];
}

function sevLabel(t: TFn, s: string): string {
  return ({ critical: t('嚴重'), high: t('高'), medium: t('中'), low: t('低'), info: t('資訊') } as Record<string, string>)[s] ?? s;
}

async function send(path: string, method: 'POST' | 'PUT' | 'DELETE', body?: unknown): Promise<{ ok: boolean; status: number; data: Record<string, unknown> }> {
  if (method === 'DELETE') {
    const res = await fetch(path, { method, headers: { 'x-asa-request': '1' }, credentials: 'same-origin' });
    return { ok: res.ok, status: res.status, data: (await res.json().catch(() => ({}))) as Record<string, unknown> };
  }
  const r = await apiPost<Record<string, unknown>>(path, body ?? {}, method);
  return r;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block space-y-1 text-sm">
      <span className="flex items-center text-xs text-slate-500">
        {label}
        {hint ? <Hint text={hint} /> : null}
      </span>
      {children}
    </label>
  );
}

/** 依頻道種類的設定欄位。 */
function ConfigFields({ t, kind, cfg, set, editing }: { t: TFn; kind: Kind; cfg: Record<string, string>; set: (k: string, v: string) => void; editing: boolean }) {
  const keep = editing ? t('留空＝不變') : undefined;
  const input = (k: string, props: { type?: string; placeholder?: string } = {}) => (
    <input className={INPUT} value={cfg[k] ?? ''} onChange={(e) => set(k, e.target.value)} autoComplete="off" {...props} />
  );
  if (kind === 'email') {
    return (
      <div className="grid gap-2 sm:grid-cols-2">
        <Field label={t('SMTP 伺服器')}>{input('host', { placeholder: 'smtp.example.com' })}</Field>
        <Field label={t('Port')} hint={t('587＝STARTTLS（大多數）；465＝一連線就 TLS（要勾下面的選項）；25＝不加密')}>
          {input('port', { placeholder: '587' })}
        </Field>
        <Field label={t('帳號')}>{input('user')}</Field>
        <Field label={t('密碼')} hint={keep}>
          {input('pass', { type: 'password', placeholder: editing ? '••••' : '' })}
        </Field>
        <Field label={t('寄件人')}>{input('from', { placeholder: 'security-hub@example.com' })}</Field>
        <Field label={t('收件人（逗號分隔）')}>{input('to', { placeholder: 'soc@example.com, it@example.com' })}</Field>
        <label className="flex items-center gap-2 text-sm sm:col-span-2">
          <input type="checkbox" checked={cfg.secure === 'true'} onChange={(e) => set('secure', e.target.checked ? 'true' : 'false')} />
          {t('一連線就使用 TLS（port 465）')}
        </label>
      </div>
    );
  }
  if (kind === 'syslog') {
    return (
      <div className="grid gap-2 sm:grid-cols-4">
        <Field label={t('主機')}>{input('host', { placeholder: 'siem.example.com' })}</Field>
        <Field label={t('Port')}>{input('port', { placeholder: '514' })}</Field>
        <Field label={t('協定')}>
          <select className={INPUT} value={cfg.protocol ?? 'udp'} onChange={(e) => set('protocol', e.target.value)}>
            <option value="udp">UDP</option>
            <option value="tcp">TCP</option>
          </select>
        </Field>
        <Field label={t('格式')} hint={t('RFC 5424 是一般 syslog；CEF 是 ArcSight、QRadar 等 SIEM 常用的格式')}>
          <select className={INPUT} value={cfg.format ?? 'rfc5424'} onChange={(e) => set('format', e.target.value)}>
            <option value="rfc5424">RFC 5424</option>
            <option value="cef">CEF</option>
          </select>
        </Field>
      </div>
    );
  }
  const urlHint =
    kind === 'slack'
      ? t('Slack 的 Incoming Webhook 網址（https://hooks.slack.com/…）')
      : kind === 'discord'
        ? t('Discord 頻道設定 → 整合 → Webhook 的網址')
        : kind === 'teams'
          ? t('Teams 的 Workflows「收到 webhook 要求時張貼到頻道」產生的網址')
          : t('收到 JSON（event、title、lines、severity、link）的網址；有填簽章金鑰時會帶 x-aism-signature 標頭');
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <Field label={t('網址')} hint={[urlHint, keep].filter(Boolean).join(' · ')}>
        {input('url', { type: 'password', placeholder: editing ? '••••' : 'https://…' })}
      </Field>
      {kind === 'webhook' ? (
        <Field label={t('簽章金鑰（選填）')} hint={t('有填時用 HMAC-SHA256 簽「時間戳.本文」，對方可以驗證訊息真的是 Hub 送的')}>
          {input('hmacSecret', { type: 'password', placeholder: editing ? '••••' : '' })}
        </Field>
      ) : null}
    </div>
  );
}

function toConfig(kind: Kind, cfg: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(cfg)) if (v !== '') out[k] = v;
  if (kind === 'email') {
    if (typeof out.to === 'string') out.to = String(out.to).split(/[,;\s]+/).filter(Boolean);
    out.secure = cfg.secure === 'true';
  }
  return out;
}

function errorText(t: TFn, r: { status: number; data: Record<string, unknown> }): string {
  const code = String(r.data.error ?? '');
  if (code.startsWith('invalid_')) return t('欄位格式不對：{f}', { f: code.slice(8) });
  if (code === 'too_many_channels' || code === 'too_many_rules') return t('數量已達上限');
  if (code === 'unknown_channel') return t('選的頻道不存在');
  return t('失敗（HTTP {n}）', { n: r.status });
}

export function NotificationSettings({ view, suggestedHubUrl, agents }: { view: NotifyView; suggestedHubUrl: string; agents: { id: string; hostname: string }[] }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [lang, setLang] = useState(view.settings.lang);
  const [hubUrl, setHubUrl] = useState(view.settings.hubUrl ?? suggestedHubUrl);
  const [newKind, setNewKind] = useState<Kind>('slack');
  const [newName, setNewName] = useState('');
  const [cfg, setCfg] = useState<Record<string, string>>({});
  const [editId, setEditId] = useState<string | null>(null);
  const [editCfg, setEditCfg] = useState<Record<string, string>>({});
  const [rule, setRule] = useState<{ name: string; event: Event; minSeverity: string; minutes: string; hour: string; agentId: string; channelIds: string[] }>({
    name: '',
    event: 'finding',
    minSeverity: 'high',
    minutes: '30',
    hour: '1',
    agentId: '',
    channelIds: [],
  });
  const channelName = (id: string) => view.channels.find((c) => c.id === id)?.name ?? '?';

  const act = (fn: () => Promise<{ ok: boolean; status: number; data: Record<string, unknown> }>, okText: string, after?: () => void) => {
    setMsg(null);
    start(async () => {
      const r = await fn();
      if (!r.ok) {
        setMsg({ ok: false, text: errorText(t, r) });
        return;
      }
      setMsg({ ok: true, text: okText });
      after?.();
      router.refresh();
    });
  };

  const test = (id: string) => {
    setMsg(null);
    start(async () => {
      const r = await send(`/api/v1/admin/notifications/channels/${id}/test`, 'POST');
      setMsg(r.data.ok ? { ok: true, text: t('測試訊息已送出，去收件的地方看看。') } : { ok: false, text: t('送不出去：{e}', { e: String(r.data.error ?? r.status) }) });
      router.refresh();
    });
  };

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        {t('發生重要的事時，Hub 每分鐘檢查一次並送通知。只通知規則建立之後發生的事；同一件事只送一次，一次檢查發現好幾件會合併成一則。')}
      </p>
      {msg ? <p className={`text-sm ${msg.ok ? 'text-green-700 dark:text-green-400' : 'text-red-600'}`}>{msg.text}</p> : null}

      <section className={BOX}>
        <h2 className="mb-3 font-semibold">{t('一般設定')}</h2>
        <div className="grid gap-2 sm:grid-cols-[10rem_1fr_auto] sm:items-end">
          <Field label={t('訊息語言')}>
            <select className={INPUT} value={lang} onChange={(e) => setLang(e.target.value as 'zh-TW' | 'en')}>
              <option value="zh-TW">繁體中文</option>
              <option value="en">English</option>
            </select>
          </Field>
          <Field label={t('Hub 網址')} hint={t('訊息裡「在 Security Hub 開啟」連結用的網址；收通知的人要能連得到')}>
            <input className={INPUT} value={hubUrl} onChange={(e) => setHubUrl(e.target.value)} placeholder="https://hub.example.com" />
          </Field>
          <button type="button" className={BTN} disabled={pending} onClick={() => act(() => send('/api/v1/admin/notifications', 'PUT', { lang, hubUrl: hubUrl.trim() || null }), t('已儲存'))}>
            {t('儲存')}
          </button>
        </div>
      </section>

      <section className={BOX}>
        <h2 className="mb-3 font-semibold">{t('頻道（送到哪）')}</h2>
        {view.channels.length ? (
          <ul className="mb-4 divide-y divide-slate-100 dark:divide-slate-800">
            {view.channels.map((c) => (
              <li key={c.id} className="space-y-2 py-2">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-medium">{c.name}</span>
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-800">{kindLabel(t, c.kind)}</span>
                  <span className="truncate font-mono text-xs text-slate-500">{c.target}</span>
                  {!c.enabled ? <span className="text-xs text-amber-700 dark:text-amber-300">{t('已停用')}</span> : null}
                  {c.lastError && (!c.lastOkAt || (c.lastErrorAt ?? '') > c.lastOkAt) ? (
                    <span className="text-xs text-red-600" title={c.lastError}>
                      {t('上次失敗 {at}：{e}', { at: since(c.lastErrorAt, t), e: c.lastError.slice(0, 80) })}
                    </span>
                  ) : c.lastOkAt ? (
                    <span className="text-xs text-green-700 dark:text-green-400">{t('上次成功 {at}', { at: since(c.lastOkAt, t) })}</span>
                  ) : null}
                  <span className="ml-auto flex gap-1">
                    <button type="button" className={SMALL} disabled={pending} onClick={() => test(c.id)}>
                      {t('送測試訊息')}
                    </button>
                    <button
                      type="button"
                      className={SMALL}
                      disabled={pending}
                      onClick={() => {
                        setEditId(editId === c.id ? null : c.id);
                        const plain: Record<string, string> = {};
                        for (const [k, v] of Object.entries(c.config)) if (typeof v !== 'string' || (!v.includes('…') && v !== '••••')) plain[k] = Array.isArray(v) ? v.join(', ') : String(v);
                        setEditCfg(plain);
                      }}
                    >
                      {t('修改')}
                    </button>
                    <button
                      type="button"
                      className={SMALL}
                      disabled={pending}
                      onClick={() => act(() => send(`/api/v1/admin/notifications/channels/${c.id}`, 'PUT', { enabled: !c.enabled }), c.enabled ? t('已停用') : t('已啟用'))}
                    >
                      {c.enabled ? t('停用') : t('啟用')}
                    </button>
                    <button
                      type="button"
                      className={DANGER}
                      disabled={pending}
                      onClick={() => window.confirm(t('刪除「{name}」？用到它的規則會拿掉這個頻道。', { name: c.name })) && act(() => send(`/api/v1/admin/notifications/channels/${c.id}`, 'DELETE'), t('已刪除'))}
                    >
                      {t('刪除')}
                    </button>
                  </span>
                </div>
                {editId === c.id ? (
                  <div className="space-y-2 rounded-lg bg-slate-50 p-3 dark:bg-slate-800/50">
                    <ConfigFields t={t} kind={c.kind as Kind} cfg={editCfg} set={(k, v) => setEditCfg({ ...editCfg, [k]: v })} editing />
                    <button
                      type="button"
                      className={BTN}
                      disabled={pending}
                      onClick={() => act(() => send(`/api/v1/admin/notifications/channels/${c.id}`, 'PUT', { config: toConfig(c.kind as Kind, editCfg) }), t('已儲存'), () => setEditId(null))}
                    >
                      {t('儲存')}
                    </button>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mb-3 text-sm text-slate-500">{t('還沒有頻道。先加一個，再建立規則。')}</p>
        )}
        <div className="space-y-2 rounded-lg border border-dashed border-slate-300 p-3 dark:border-slate-700">
          <h3 className="text-sm font-medium">{t('新增頻道')}</h3>
          <div className="grid gap-2 sm:grid-cols-2">
            <Field label={t('種類')}>
              <select
                className={INPUT}
                value={newKind}
                onChange={(e) => {
                  setNewKind(e.target.value as Kind);
                  setCfg({});
                }}
              >
                {KINDS.map((k) => (
                  <option key={k} value={k}>
                    {kindLabel(t, k)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label={t('名稱')}>
              <input className={INPUT} value={newName} onChange={(e) => setNewName(e.target.value)} placeholder={t('例：資安群組')} />
            </Field>
          </div>
          <ConfigFields t={t} kind={newKind} cfg={cfg} set={(k, v) => setCfg({ ...cfg, [k]: v })} editing={false} />
          <button
            type="button"
            className={BTN}
            disabled={pending || !newName.trim()}
            onClick={() =>
              act(() => send('/api/v1/admin/notifications/channels', 'POST', { kind: newKind, name: newName.trim(), config: toConfig(newKind, cfg) }), t('已新增，可以按「送測試訊息」試試看'), () => {
                setNewName('');
                setCfg({});
              })
            }
          >
            {t('新增頻道')}
          </button>
          <p className="text-xs text-slate-500">{t('密碼與 webhook 網址加密存放，之後網頁上只顯示遮罩。')}</p>
        </div>
      </section>

      <section className={BOX}>
        <h2 className="mb-3 font-semibold">{t('規則（什麼事要通知）')}</h2>
        {view.rules.length ? (
          <ul className="mb-4 divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {view.rules.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-2 py-2">
                <span className="font-medium">{r.name}</span>
                <span className="rounded bg-violet-50 px-1.5 py-0.5 text-xs text-violet-800 dark:bg-violet-950/50 dark:text-violet-300">{eventLabel(t, r.event)}</span>
                {r.event === 'finding' && r.minSeverity ? <span className="text-xs text-slate-500">{t('{s} 以上', { s: sevLabel(t, r.minSeverity) })}</span> : null}
                {r.event === 'host_offline' ? <span className="text-xs text-slate-500">{t('{n} 分鐘', { n: Number(r.params.minutes ?? 30) })}</span> : null}
                {r.event === 'daily_digest' ? <span className="text-xs text-slate-500">{t('每天 {h}:00 UTC', { h: Number(r.params.hour ?? 9) })}</span> : null}
                {r.agentId ? <span className="text-xs text-slate-500">{agents.find((a) => a.id === r.agentId)?.hostname ?? r.agentId}</span> : null}
                <span className="text-xs text-slate-500">→ {r.channelIds.length ? r.channelIds.map(channelName).join('、') : t('（沒有頻道，不會送）')}</span>
                {!r.enabled ? <span className="text-xs text-amber-700 dark:text-amber-300">{t('已停用')}</span> : null}
                <span className="ml-auto flex gap-1">
                  <button
                    type="button"
                    className={SMALL}
                    disabled={pending}
                    onClick={() => act(() => send(`/api/v1/admin/notifications/rules/${r.id}`, 'PUT', { enabled: !r.enabled }), r.enabled ? t('已停用') : t('已啟用'))}
                  >
                    {r.enabled ? t('停用') : t('啟用')}
                  </button>
                  <button
                    type="button"
                    className={DANGER}
                    disabled={pending}
                    onClick={() => window.confirm(t('刪除規則「{name}」？', { name: r.name })) && act(() => send(`/api/v1/admin/notifications/rules/${r.id}`, 'DELETE'), t('已刪除'))}
                  >
                    {t('刪除')}
                  </button>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mb-3 text-sm text-slate-500">{t('還沒有規則。')}</p>
        )}
        <div className="space-y-2 rounded-lg border border-dashed border-slate-300 p-3 dark:border-slate-700">
          <h3 className="text-sm font-medium">{t('新增規則')}</h3>
          <div className="grid gap-2 sm:grid-cols-3">
            <Field label={t('名稱')}>
              <input className={INPUT} value={rule.name} onChange={(e) => setRule({ ...rule, name: e.target.value })} placeholder={t('例：嚴重問題通知資安群組')} />
            </Field>
            <Field label={t('事件')} hint={eventHint(t, rule.event)}>
              <select className={INPUT} value={rule.event} onChange={(e) => setRule({ ...rule, event: e.target.value as Event })}>
                {EVENTS.map((e) => (
                  <option key={e} value={e}>
                    {eventLabel(t, e)}
                  </option>
                ))}
              </select>
            </Field>
            {rule.event === 'finding' ? (
              <Field label={t('嚴重度至少')}>
                <select className={INPUT} value={rule.minSeverity} onChange={(e) => setRule({ ...rule, minSeverity: e.target.value })}>
                  {SEVS.map((s) => (
                    <option key={s} value={s}>
                      {sevLabel(t, s)}
                    </option>
                  ))}
                </select>
              </Field>
            ) : rule.event === 'host_offline' ? (
              <Field label={t('多久沒回報（分鐘）')}>
                <input className={INPUT} type="number" min={5} value={rule.minutes} onChange={(e) => setRule({ ...rule, minutes: e.target.value })} />
              </Field>
            ) : rule.event === 'daily_digest' ? (
              <Field label={t('幾點送（UTC，0–23）')} hint={t('台灣時間＝UTC＋8，例如早上 9 點填 1')}>
                <input className={INPUT} type="number" min={0} max={23} value={rule.hour} onChange={(e) => setRule({ ...rule, hour: e.target.value })} />
              </Field>
            ) : (
              <span />
            )}
            {['finding', 'dangerous_connection', 'host_offline', 'action_pending'].includes(rule.event) ? (
              <Field label={t('只看這台主機（選填）')}>
                <select className={INPUT} value={rule.agentId} onChange={(e) => setRule({ ...rule, agentId: e.target.value })}>
                  <option value="">{t('所有主機')}</option>
                  {agents.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.hostname}
                    </option>
                  ))}
                </select>
              </Field>
            ) : null}
          </div>
          <fieldset className="flex flex-wrap gap-3 text-sm">
            <legend className="mb-1 text-xs text-slate-500">{t('送到')}</legend>
            {view.channels.map((c) => (
              <label key={c.id} className="flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={rule.channelIds.includes(c.id)}
                  onChange={(e) => setRule({ ...rule, channelIds: e.target.checked ? [...rule.channelIds, c.id] : rule.channelIds.filter((x) => x !== c.id) })}
                />
                {c.name}
              </label>
            ))}
            {!view.channels.length ? <span className="text-xs text-slate-500">{t('先新增頻道')}</span> : null}
          </fieldset>
          <button
            type="button"
            className={BTN}
            disabled={pending || !rule.name.trim() || !rule.channelIds.length}
            onClick={() =>
              act(
                () =>
                  send('/api/v1/admin/notifications/rules', 'POST', {
                    name: rule.name.trim(),
                    event: rule.event,
                    minSeverity: rule.event === 'finding' ? rule.minSeverity : null,
                    agentId: rule.agentId || null,
                    channelIds: rule.channelIds,
                    params:
                      rule.event === 'host_offline' ? { minutes: Number(rule.minutes) || 30 } : rule.event === 'daily_digest' ? { hour: Number(rule.hour) || 0 } : {},
                  }),
                t('已新增規則'),
                () => setRule({ ...rule, name: '' }),
              )
            }
          >
            {t('新增規則')}
          </button>
        </div>
      </section>

      <section className={BOX}>
        <h2 className="mb-3 font-semibold">{t('最近送出的通知')}</h2>
        {view.log.length ? (
          <div className="-mx-2 overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500">
                  <th className="px-2 py-1">{t('時間')}</th>
                  <th className="px-2 py-1">{t('標題')}</th>
                  <th className="px-2 py-1">{t('頻道')}</th>
                  <th className="px-2 py-1">{t('狀態')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {view.log.map((l) => (
                  <tr key={l.id}>
                    <td className="whitespace-nowrap px-2 py-1.5 text-xs text-slate-500">{since(l.createdAt, t)}</td>
                    <td className="px-2 py-1.5">{l.title}</td>
                    <td className="px-2 py-1.5 text-xs">{channelName(l.channelId)}</td>
                    <td className="px-2 py-1.5 text-xs" title={l.error ?? undefined}>
                      {l.status === 'sent' ? (
                        <span className="text-green-700 dark:text-green-400">{t('已送出')}</span>
                      ) : l.status === 'failed' ? (
                        <span className="text-red-600">{t('失敗：{e}', { e: (l.error ?? '').slice(0, 60) })}</span>
                      ) : (
                        <span className="text-amber-700 dark:text-amber-300">{t('等待重試（第 {n} 次）', { n: l.attempts })}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-slate-500">{t('還沒有送過通知。')}</p>
        )}
      </section>
    </div>
  );
}
