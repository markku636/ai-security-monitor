'use client';

// 「設定與金鑰 → 防護 DNS」：封鎖開關與暫停、連上來的防護 DNS 伺服器、最近 24 小時的封鎖、被擋的查詢（一鍵放行）、
// 上游與清單設定、部署教學。關掉或暫停時伺服器照常轉送（只是不封鎖），正在用它的裝置不會斷網。
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useState, useTransition, type ReactNode } from 'react';
import { Hint, Term } from '@/components/ui/Hint';
import { apiPost } from '@/lib/api-client';
import type { ProtectView } from '@/lib/dns/protect';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { useT } from '@/lib/i18n/client';

const INPUT = 'w-full rounded-md border border-slate-300 bg-white px-2 py-1 font-mono text-xs dark:border-slate-700 dark:bg-slate-900';
const BTN = 'whitespace-nowrap rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const SMALL = 'whitespace-nowrap rounded-md border border-slate-300 px-2 py-0.5 text-xs hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:hover:bg-slate-800';
const BOX = 'rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900';
const TH = 'px-2 py-1 text-left text-xs font-medium text-slate-500';
const TD = 'px-2 py-1 align-top';

type Status = {
  blocking?: boolean;
  blocklist_entries?: number;
  lists_loaded?: string[];
  lists_missing?: string[];
  listen?: string[];
  upstreams?: { upstream: string; ewma_ms: number; failures: number }[];
  stats?: { queries?: number; blocked?: number; cache_hits?: number; cache_misses?: number; hit_p99_us?: number | null; miss_p50_us?: number | null };
};

const lines = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
const n = (v: number | undefined | null) => (v ?? 0).toLocaleString();
const ms = (us: number | null | undefined) => (us == null ? '—' : us < 1000 ? `${us} µs` : `${Math.round(us / 1000)} ms`);

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

function remaining(until: string | null, now: number): number {
  return until ? Math.max(0, Date.parse(until) - now) : 0;
}

function stateText(t: TFn, v: ProtectView, left: number): { text: string; tone: string } {
  if (!v.servers.length) return { text: t('還沒有防護 DNS 連上來'), tone: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300' };
  if (!v.settings.enabled) return { text: t('封鎖已關閉（只轉送）'), tone: 'bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300' };
  if (left > 0) {
    const m = Math.floor(left / 60_000);
    const s = Math.floor((left % 60_000) / 1000);
    return { text: t('暫停中，{t} 後恢復封鎖', { t: `${m}:${String(s).padStart(2, '0')}` }), tone: 'bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300' };
  }
  return { text: t('封鎖中'), tone: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300' };
}

export function DnsProtectSettings({ view, hubUrl }: { view: ProtectView; hubUrl: string }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const s = view.settings;
  const [form, setForm] = useState({
    upstreams: s.upstreams.join('\n'),
    feeds: s.feeds,
    minConfidence: String(s.min_confidence),
    block: s.block.join('\n'),
    allow: s.allow.join('\n'),
    internal: s.internal_suffixes.join('\n'),
    privateRelay: s.block_private_relay,
    log: s.log,
    resolvers: s.resolver_ips.join('\n'),
  });
  const left = remaining(s.paused_until, now);
  useEffect(() => {
    if (left <= 0) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [left]);
  useEffect(() => {
    if (s.paused_until && left === 0) router.refresh();
  }, [left, s.paused_until, router]);

  const send = (path: string, method: 'POST' | 'PUT', body: unknown, okText: string) => {
    setMsg(null);
    start(async () => {
      const r = await apiPost<{ error?: string }>(path, body, method);
      setMsg(r.ok ? { ok: true, text: okText } : { ok: false, text: r.data.error?.startsWith('invalid:') ? t('格式不對：{f}', { f: r.data.error.slice(8) }) : t('失敗（HTTP {n}）', { n: r.status }) });
      if (r.ok) router.refresh();
    });
  };
  const put = (patch: Record<string, unknown>, okText = t('已儲存')) => send('/api/v1/admin/dns-protect', 'PUT', patch, okText);
  const pause = (minutes: number) => send('/api/v1/admin/dns-protect', 'POST', { pause_minutes: minutes }, minutes ? t('已暫停封鎖') : t('已恢復封鎖'));
  const save = () =>
    put({
      upstreams: lines(form.upstreams),
      feeds: form.feeds,
      min_confidence: Number(form.minConfidence),
      block: lines(form.block),
      allow: lines(form.allow),
      internal_suffixes: lines(form.internal),
      block_private_relay: form.privateRelay,
      log: form.log,
      resolver_ips: lines(form.resolvers),
    });
  const st = stateText(t, view, left);
  const autoFeeds = view.feeds.filter((f) => f.auto).map((f) => f.name);

  return (
    <div className="space-y-4">
      <section className={BOX}>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-base font-semibold">{t('防護 DNS')}</h2>
          <Hint text={t('給整個區網用的 DNS 伺服器：把電腦、手機、IoT 的 DNS 指到它，查到威脅情資列名的網域就擋掉（回「查無此網域」），其他照常經加密 DNS 轉送並快取。')} />
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${st.tone}`}>{st.text}</span>
        </div>
        <p className="mt-1 text-sm text-slate-500">
          {t('關掉或暫停時，伺服器照常')}
          <Term hint={t('把查詢轉給上游 DNS（預設 Quad9 與 Cloudflare 的加密 DNS）再把答案交回，裝置照常上網。')}>{t('轉送')}</Term>
          {t('，只是不封鎖，所以正在用它的裝置不會斷網。')}
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {s.enabled ? (
            <button type="button" className={SMALL} disabled={pending} onClick={() => put({ enabled: false, paused_until: null }, t('已關閉封鎖'))}>
              {t('關閉封鎖')}
            </button>
          ) : (
            <button type="button" className={BTN} disabled={pending} onClick={() => put({ enabled: true }, t('已開啟封鎖'))}>
              {t('開啟封鎖')}
            </button>
          )}
          {s.enabled && left === 0 ? (
            <>
              <button type="button" className={SMALL} disabled={pending} onClick={() => pause(5)}>
                {t('暫停 5 分鐘')}
              </button>
              <button type="button" className={SMALL} disabled={pending} onClick={() => pause(60)}>
                {t('暫停 1 小時')}
              </button>
            </>
          ) : null}
          {left > 0 ? (
            <button type="button" className={SMALL} disabled={pending} onClick={() => pause(0)}>
              {t('立即恢復')}
            </button>
          ) : null}
        </div>
        {msg ? <p className={`mt-2 text-sm ${msg.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-600'}`}>{msg.text}</p> : null}
      </section>

      <section className={BOX}>
        <h3 className="mb-2 text-sm font-semibold">{t('伺服器')}</h3>
        {view.servers.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr>
                  <th className={TH}>{t('名稱')}</th>
                  <th className={TH}>{t('狀態')}</th>
                  <th className={TH}>{t('查詢')}</th>
                  <th className={TH}>
                    {t('快取命中')}
                    <Hint text={t('從快取直接回答的比例；越高越快、越少送到上游。')} />
                  </th>
                  <th className={TH}>{t('封鎖')}</th>
                  <th className={TH}>
                    {t('延遲')}
                    <Hint text={t('快取命中的 p99（99% 的查詢在這個時間內回答）／沒命中時 p50（一半的查詢在這個時間內，含上游）。')} />
                  </th>
                  <th className={TH}>{t('封鎖清單')}</th>
                  <th className={TH}>{t('上游')}</th>
                </tr>
              </thead>
              <tbody>
                {view.servers.map((srv) => {
                  const x = srv.status as Status;
                  const hits = x.stats?.cache_hits ?? 0;
                  const total = hits + (x.stats?.cache_misses ?? 0);
                  return (
                    <tr key={srv.id} className="border-t border-slate-100 dark:border-slate-800">
                      <td className={TD}>
                        <div className="font-medium">{srv.name}</div>
                        <div className="text-xs text-slate-500">
                          {[srv.hostname, srv.sourceIp, srv.version && `v${srv.version}`].filter(Boolean).join(' · ')}
                        </div>
                        {x.listen?.length ? <div className="font-mono text-xs text-slate-500">{x.listen.join(', ')}</div> : null}
                      </td>
                      <td className={TD}>
                        <span className={srv.online ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-600'}>{srv.online ? t('在線') : t('離線')}</span>
                        <div className="text-xs text-slate-500">{since(srv.lastSeenAt, t)}</div>
                      </td>
                      <td className={TD}>{n(x.stats?.queries)}</td>
                      <td className={TD}>{total ? `${Math.round((hits / total) * 100)}%` : '—'}</td>
                      <td className={TD}>{n(x.stats?.blocked)}</td>
                      <td className={TD}>
                        {ms(x.stats?.hit_p99_us)} / {ms(x.stats?.miss_p50_us)}
                      </td>
                      <td className={TD}>
                        {n(x.blocklist_entries)}
                        <div className="text-xs text-slate-500">{(x.lists_loaded ?? []).join(', ')}</div>
                        {x.lists_missing?.length ? <div className="text-xs text-amber-700 dark:text-amber-400">{t('還沒下載：{l}', { l: x.lists_missing.join(', ') })}</div> : null}
                      </td>
                      <td className={TD}>
                        {(x.upstreams ?? []).map((u) => (
                          <div key={u.upstream} className="text-xs">
                            <span className="font-mono">{u.upstream}</span> {u.ewma_ms} ms
                          </div>
                        ))}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-slate-500">{t('還沒有防護 DNS 連上來。照下面「怎麼部署」起一台，約 30 秒內會出現在這裡。')}</p>
        )}
      </section>

      <section className={BOX}>
        <h3 className="mb-2 text-sm font-semibold">{t('最近 24 小時')}</h3>
        <div className="flex flex-wrap gap-6 text-sm">
          <div>
            <div className="text-xs text-slate-500">{t('查詢')}</div>
            <div className="text-lg font-semibold">{n(view.stats.queries)}</div>
          </div>
          <div>
            <div className="text-xs text-slate-500">{t('封鎖')}</div>
            <div className="text-lg font-semibold">{n(view.stats.blocked)}</div>
          </div>
          <div>
            <div className="text-xs text-slate-500">{t('裝置')}</div>
            <div className="text-lg font-semibold">{n(view.stats.clients)}</div>
          </div>
        </div>
        <div className="mt-3 grid gap-4 md:grid-cols-2">
          <div>
            <h4 className="mb-1 text-xs font-medium text-slate-500">{t('被擋最多的網域')}</h4>
            {view.stats.topBlocked.length ? (
              <ul className="space-y-0.5 text-sm">
                {view.stats.topBlocked.map((d) => (
                  <li key={d.registrable} className="flex justify-between gap-2">
                    <Link className="truncate font-mono text-xs text-teal-700 hover:underline dark:text-teal-400" href={`/domain/${encodeURIComponent(d.registrable)}`}>
                      {d.registrable}
                    </Link>
                    <span className="whitespace-nowrap text-xs text-slate-500">
                      {n(d.count)} · {d.by}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-500">{t('沒有')}</p>
            )}
          </div>
          <div>
            <h4 className="mb-1 text-xs font-medium text-slate-500">{t('查詢最多的裝置')}</h4>
            {view.stats.topClients.length ? (
              <ul className="space-y-0.5 text-sm">
                {view.stats.topClients.map((c) => (
                  <li key={c.client} className="flex justify-between gap-2">
                    <span className="truncate">
                      <span className="font-mono text-xs">{c.client}</span>{' '}
                      {c.agentId ? (
                        <Link className="text-xs text-teal-700 hover:underline dark:text-teal-400" href={`/agents/${c.agentId}`}>
                          {c.hostname}
                        </Link>
                      ) : (
                        <span className="text-xs text-slate-500">{t('（沒裝 agent 的裝置）')}</span>
                      )}
                    </span>
                    <span className="whitespace-nowrap text-xs text-slate-500">
                      {n(c.queries)} / {t('擋 {n}', { n: c.blocked })}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-500">{t('沒有')}</p>
            )}
          </div>
        </div>
      </section>

      <section className={BOX}>
        <h3 className="mb-2 text-sm font-semibold">
          {t('最近被擋的查詢')}
          <Hint text={t('擋錯了就按「放行」：把這個網域加進白名單（含子網域），1 分鐘內所有防護 DNS 都會生效。')} />
        </h3>
        {view.recentBlocked.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr>
                  <th className={TH}>{t('時間')}</th>
                  <th className={TH}>{t('裝置')}</th>
                  <th className={TH}>{t('網域')}</th>
                  <th className={TH}>{t('原因')}</th>
                  <th className={TH} />
                </tr>
              </thead>
              <tbody>
                {view.recentBlocked.map((b) => (
                  <tr key={`${b.ts}|${b.client}|${b.name}`} className="border-t border-slate-100 dark:border-slate-800">
                    <td className={`${TD} whitespace-nowrap text-xs text-slate-500`}>{since(b.ts, t)}</td>
                    <td className={`${TD} text-xs`}>
                      <span className="font-mono">{b.client}</span> {b.hostname ?? ''}
                    </td>
                    <td className={`${TD} font-mono text-xs`}>{b.name}</td>
                    <td className={`${TD} text-xs`}>{b.blockedBy}</td>
                    <td className={TD}>
                      <button
                        type="button"
                        className={SMALL}
                        disabled={pending || s.allow.includes(b.registrable)}
                        onClick={() => put({ allow: [...s.allow, b.registrable] }, t('已放行 {d}', { d: b.registrable }))}
                      >
                        {s.allow.includes(b.registrable) ? t('已放行') : t('放行')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-slate-500">{t('沒有')}</p>
        )}
      </section>

      <section className={`${BOX} space-y-3`}>
        <h3 className="text-sm font-semibold">{t('設定')}</h3>
        <div className="grid gap-3 md:grid-cols-2">
          <Field label={t('上游 DNS（一行一個；空白＝預設）')} hint={t('https:// 開頭＝加密 DNS（DoH），否則填 IP。預設：{d}', { d: view.defaultUpstreams.join('、') })}>
            <textarea className={INPUT} rows={3} value={form.upstreams} placeholder={view.defaultUpstreams.join('\n')} onChange={(e) => setForm({ ...form, upstreams: e.target.value })} />
          </Field>
          <Field
            label={t('裝置要用的 DNS 位址（一行一個）')}
            hint={t('這些電腦執行 ai-security-monitor dns use-hub 時會把 DNS 指到這裡；有填時，沒在用它的主機會出現「沒有用公司的防護 DNS」提醒。填防護 DNS 在區網的 IP。')}
          >
            <textarea className={INPUT} rows={3} value={form.resolvers} placeholder={view.suggestedResolvers.join('\n')} onChange={(e) => setForm({ ...form, resolvers: e.target.value })} />
            {view.suggestedResolvers.length && !form.resolvers.trim() ? (
              <button type="button" className={`${SMALL} mt-1`} onClick={() => setForm({ ...form, resolvers: view.suggestedResolvers.join('\n') })}>
                {t('填入建議：{l}', { l: view.suggestedResolvers.join('、') })}
              </button>
            ) : null}
          </Field>
          <Field label={t('內部網域（一行一個）')} hint={t('公司內部的網域（例 corp.example）解析到私有 IP 是正常的；其他公網網域回私有 IP 會被當成 DNS rebinding 擋掉。')}>
            <textarea className={INPUT} rows={3} value={form.internal} onChange={(e) => setForm({ ...form, internal: e.target.value })} />
          </Field>
          <Field label={t('自訂封鎖（一行一個，含子網域）')}>
            <textarea className={INPUT} rows={4} value={form.block} onChange={(e) => setForm({ ...form, block: e.target.value })} />
          </Field>
          <Field label={t('白名單（一行一個，含子網域）')} hint={t('永遠不擋；情資清單誤判時加在這裡。')}>
            <textarea className={INPUT} rows={4} value={form.allow} onChange={(e) => setForm({ ...form, allow: e.target.value })} />
          </Field>
        </div>
        <fieldset className="space-y-1 text-sm">
          <legend className="flex items-center text-xs text-slate-500">
            {t('封鎖用的情資清單')}
            <Hint text={t('都不勾＝自動：已啟用、信心至少 {n}、授權允許商用的網域清單（目前：{l}）。非商用授權的清單只告警、不拿來封鎖。', { n: form.minConfidence, l: autoFeeds.join('、') || t('無') })} />
          </legend>
          <div className="grid gap-1 md:grid-cols-2">
            {view.feeds.map((f) => (
              <label key={f.id} className="inline-flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.feeds.includes(f.id)}
                  onChange={(e) => setForm({ ...form, feeds: e.target.checked ? [...form.feeds, f.id] : form.feeds.filter((x) => x !== f.id) })}
                />
                <span>
                  {f.name} <span className="text-xs text-slate-500">({t('信心 {n}', { n: f.confidence })} · {f.license}{f.commercial_ok ? '' : ` · ${t('非商用')}`})</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="flex flex-wrap items-end gap-4">
          <Field label={t('自動挑選的最低信心')}>
            <input className={`${INPUT} w-24`} type="number" min={40} max={100} value={form.minConfidence} onChange={(e) => setForm({ ...form, minConfidence: e.target.value })} />
          </Field>
          <label className="inline-flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.privateRelay} onChange={(e) => setForm({ ...form, privateRelay: e.target.checked })} />
            {t('也擋 iCloud 私密轉送')}
            <Hint text={t('Apple 裝置開了 iCloud 私密轉送時會繞過這台 DNS；擋掉它的網域，Safari 會改回用這台 DNS。')} />
          </label>
          <label className="inline-flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.log} onChange={(e) => setForm({ ...form, log: e.target.checked })} />
            {t('記錄查詢並上傳 Hub')}
            <Hint text={t('查詢紀錄等於上網紀錄，公司部署前請先告知員工。關掉後只送統計數字。')} />
          </label>
          <button type="button" className={BTN} disabled={pending} onClick={save}>
            {t('儲存')}
          </button>
        </div>
      </section>

      <details className={BOX}>
        <summary className="cursor-pointer text-sm font-semibold">{t('怎麼部署')}</summary>
        <div className="mt-2 space-y-3 text-sm">
          <div>
            <h4 className="font-medium">{t('1. 在一台常開的電腦上跑防護 DNS')}</h4>
            <p className="text-slate-500">{t('到「API token」分頁建立權杖、權限勾「防護 DNS 伺服器」，再用系統管理員（root）執行：')}</p>
            <pre className="mt-1 overflow-x-auto rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{`ai-security-monitor dns-server --hub ${hubUrl || 'https://<hub>'} --hub-token <TOKEN>`}</pre>
            <p className="text-xs text-slate-500">{t('建議原生跑：看得到每個裝置的真實 IP。Windows／macOS 的 Docker Desktop 會把來源都變成同一個位址。')}</p>
            <p className="mt-1 text-slate-500">{t('已加入這個 Hub 的電腦，也可以交給背景服務帶起（掛掉自動重啟）：')}</p>
            <pre className="mt-1 overflow-x-auto rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{'ai-security-monitor config set dns.server.enabled true'}</pre>
            <p className="mt-1 text-slate-500">{t('或用 Hub 的 compose：.env 設 AI_SECURITY_MONITOR_HUB_DNS_TOKEN（至少 32 字元）與 AI_SECURITY_MONITOR_HUB_DNS_BIND（這台的區網 IP），改用含防護 DNS 的 docker/compose.dns.yml（單機版 compose.standalone.dns.yml）啟動。')}</p>
            {view.composeTokenConfigured ? <p className="text-xs text-emerald-700 dark:text-emerald-400">{t('這個 Hub 已設定 compose 的防護 DNS 權杖。')}</p> : null}
          </div>
          <div>
            <h4 className="font-medium">{t('2. 把裝置的 DNS 指到它')}</h4>
            <p className="text-slate-500">{t('個別電腦：在那台以系統管理員執行（會記下原設定；防護 DNS 連續 3 分鐘查不到會自動改回）：')}</p>
            <pre className="mt-1 overflow-x-auto rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{'ai-security-monitor dns use-hub --yes\nai-security-monitor dns restore --yes   # ' + t('改回原本的 DNS')}</pre>
            <p className="text-slate-500">
              {t('最省事是在路由器的 DHCP 設定把 DNS 伺服器改成這台電腦的區網 IP。有 IPv6 的話，路由器的')}
              <Term hint={t('IPv6 的路由器通告會告訴裝置用哪台 DNS（RDNSS），DHCPv6 也可能另外給一組；沒改的話裝置會走 IPv6 的 DNS，繞過防護。')}>{t('IPv6 DNS（RDNSS／DHCPv6）')}</Term>
              {t('也要指過來，不然會被繞過。')}
            </p>
          </div>
          <div>
            <h4 className="font-medium">{t('3. 測試')}</h4>
            <pre className="mt-1 overflow-x-auto rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{`nslookup blocked-test.asm-dns.invalid <DNS IP>   # ${t('應該查無此網域（NXDOMAIN）')}\nnslookup example.com <DNS IP>                    # ${t('應該有答案')}`}</pre>
          </div>
        </div>
      </details>
    </div>
  );
}
