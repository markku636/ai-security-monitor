'use client';

// 「設定與金鑰 → 自動回應」：全域開關與白名單、主機群組、規則、自動封鎖紀錄（可立即解除）。
import { useRouter } from 'next/navigation';
import { useState, useTransition, type ReactNode } from 'react';
import { Hint } from '@/components/ui/Hint';
import { apiPost } from '@/lib/api-client';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { useT } from '@/lib/i18n/client';
import type { ResponseView } from '@/lib/response/admin';

const INPUT = 'w-full rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900';
const BTN = 'whitespace-nowrap rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const SMALL = 'whitespace-nowrap rounded-md border border-slate-300 px-2 py-0.5 text-xs hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:hover:bg-slate-800';
const DANGER = 'whitespace-nowrap rounded-md border border-red-300 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950/40';
const BOX = 'rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900';

type Trigger = 'intel_inbound' | 'bruteforce' | 'finding';
const TRIGGERS: Trigger[] = ['bruteforce', 'intel_inbound', 'finding'];

function triggerLabel(t: TFn, k: string): string {
  return ({ intel_inbound: t('情資列名的來源連進來'), bruteforce: t('暴力破解來源'), finding: t('指定的問題規則') } as Record<string, string>)[k] ?? k;
}

function triggerHint(t: TFn, k: Trigger): string {
  return {
    intel_inbound: t('最新連線快照裡，有被威脅情資列名的 IP 連進這台主機。'),
    bruteforce: t('事件記錄裡同一個來源 IP 登入失敗次數達到門檻（Windows 登入失敗、NTLM 失敗）。'),
    finding: t('出現指定規則的問題（例 intel.inbound_match，可用 * 結尾），封鎖問題裡的 IP。'),
  }[k];
}

async function send(path: string, method: 'POST' | 'PUT' | 'DELETE', body?: unknown) {
  if (method === 'DELETE') {
    const res = await fetch(path, { method, headers: { 'x-asa-request': '1' }, credentials: 'same-origin' });
    return { ok: res.ok, status: res.status, data: (await res.json().catch(() => ({}))) as Record<string, unknown> };
  }
  return apiPost<Record<string, unknown>>(path, body ?? {}, method);
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

interface GroupForm {
  id: string | null;
  name: string;
  members: string[];
  scan_interval: string;
  snapshot_interval: string;
  fim_enabled: string;
  dns_names: string;
  fim_extra_paths: string;
  fim_ignore: string;
}

const EMPTY_GROUP: GroupForm = { id: null, name: '', members: [], scan_interval: '', snapshot_interval: '', fim_enabled: '', dns_names: '', fim_extra_paths: '', fim_ignore: '' };

function groupForm(g: ResponseView['groups'][number]): GroupForm {
  const c = (g.config ?? {}) as Record<string, unknown>;
  const str = (k: string) => (typeof c[k] === 'string' ? (c[k] as string) : '');
  const bool = (k: string) => (typeof c[k] === 'boolean' ? String(c[k]) : '');
  const lines = (k: string) => (Array.isArray(c[k]) ? (c[k] as string[]).join('\n') : '');
  return {
    id: g.id,
    name: g.name,
    members: g.members,
    scan_interval: str('scan_interval'),
    snapshot_interval: str('snapshot_interval'),
    fim_enabled: bool('fim_enabled'),
    dns_names: bool('dns_names'),
    fim_extra_paths: lines('fim_extra_paths'),
    fim_ignore: lines('fim_ignore'),
  };
}

/** 表單 → 集中設定（空的欄位不送）。 */
function centralOf(g: GroupForm): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (g.scan_interval.trim()) out.scan_interval = g.scan_interval.trim();
  if (g.snapshot_interval.trim()) out.snapshot_interval = g.snapshot_interval.trim();
  if (g.fim_enabled) out.fim_enabled = g.fim_enabled === 'true';
  if (g.dns_names) out.dns_names = g.dns_names === 'true';
  const lines = (v: string) => v.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  if (lines(g.fim_extra_paths).length) out.fim_extra_paths = lines(g.fim_extra_paths);
  if (lines(g.fim_ignore).length) out.fim_ignore = lines(g.fim_ignore);
  return out;
}

function errorText(t: TFn, r: { status: number; data: Record<string, unknown> }): string {
  const code = String(r.data.error ?? '');
  if (code === 'bad_cidr' || code === 'cidr_too_broad') return t('白名單網段格式不對或範圍太大');
  if (code.startsWith('invalid_params')) return t('「指定的問題規則」要填規則名稱');
  if (code === 'unknown_group') return t('選的群組不存在');
  if (code === 'bad_request' && String(r.data.field ?? '').startsWith('config')) return t('集中設定的格式不對：間隔要像 30m、2h，掃描最短 5 分鐘、快照最短 30 秒');
  if (code.startsWith('too_many')) return t('數量已達上限');
  return t('失敗（HTTP {n}）', { n: r.status });
}

export function AutoResponseSettings({ view }: { view: ResponseView }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [allow, setAllow] = useState(view.settings.allowlist.join('\n'));
  const [group, setGroup] = useState<GroupForm>(EMPTY_GROUP);
  const [rule, setRule] = useState({ name: '', trigger: 'bruteforce' as Trigger, threshold: '10', pattern: 'intel.inbound_match', blockMinutes: '60', escalate: true, groupId: '' });
  const groupName = (id: string | null) => view.groups.find((g) => g.id === id)?.name ?? '';
  const noAccept = view.hosts.filter((h) => !h.acceptsActions);
  const active = view.blocks.filter((b) => b.status === 'active');

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

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        {t('符合規則時，Hub 自動替主機建立並核准「封鎖 IP」，時間到自動解除。只封公網 IP；內網、保留位址與白名單網段一律不封；只對同意遠端動作的主機有作用。每一步都記在稽核紀錄。')}
      </p>
      {msg ? <p className={`text-sm ${msg.ok ? 'text-green-700 dark:text-green-400' : 'text-red-600'}`}>{msg.text}</p> : null}

      <section className={BOX}>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="font-semibold">{t('自動回應')}</h2>
          <span className={`rounded-full px-2 py-0.5 text-xs ${view.settings.enabled ? 'bg-red-600 text-white' : 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200'}`}>
            {view.settings.enabled ? t('已開啟') : t('已關閉（預設）')}
          </span>
          <button
            type="button"
            className={view.settings.enabled ? SMALL : BTN}
            disabled={pending}
            onClick={() =>
              (view.settings.enabled || window.confirm(t('開啟後，符合規則的 IP 會在沒有人工確認的情況下被封鎖。確定開啟？'))) &&
              act(() => send('/api/v1/admin/response', 'PUT', { enabled: !view.settings.enabled }), view.settings.enabled ? t('已關閉；目前的封鎖到期後照常解除') : t('已開啟'))
            }
          >
            {view.settings.enabled ? t('關閉') : t('開啟')}
          </button>
        </div>
        {noAccept.length ? (
          <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">
            {t('這些主機沒有同意遠端動作，自動回應對它們不會作用：{hosts}', { hosts: noAccept.map((h) => h.hostname).join('、') })}
          </p>
        ) : null}
        <div className="mt-3 grid gap-2 sm:grid-cols-[1fr_auto] sm:items-end">
          <Field label={t('白名單網段（一行一個）')} hint={t('永遠不封的網段，例如公司對外 IP、合作夥伴、監控服務。格式 203.0.113.0/24。')}>
            <textarea className={`${INPUT} font-mono`} rows={3} value={allow} onChange={(e) => setAllow(e.target.value)} placeholder="203.0.113.0/24" />
          </Field>
          <button
            type="button"
            className={BTN}
            disabled={pending}
            onClick={() => act(() => send('/api/v1/admin/response', 'PUT', { allowlist: allow.split(/\s+/).filter(Boolean) }), t('已儲存'))}
          >
            {t('儲存白名單')}
          </button>
        </div>
      </section>

      <section className={BOX}>
        <h2 className="mb-3 font-semibold">{t('目前的封鎖')}</h2>
        {view.blocks.length ? (
          <div className="-mx-2 overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500">
                  <th className="px-2 py-1">{t('主機')}</th>
                  <th className="px-2 py-1">IP</th>
                  <th className="px-2 py-1">{t('原因')}</th>
                  <th className="px-2 py-1">{t('封鎖時間')}</th>
                  <th className="px-2 py-1">{t('狀態')}</th>
                  <th className="px-2 py-1" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {view.blocks.slice(0, 50).map((b) => (
                  <tr key={b.id}>
                    <td className="px-2 py-1.5">{b.hostname}</td>
                    <td className="px-2 py-1.5 font-mono text-xs">
                      <a href={`/ip/${encodeURIComponent(b.ip)}`} className="hover:underline">
                        {b.ip}
                      </a>
                    </td>
                    <td className="px-2 py-1.5 text-xs">
                      {b.reason}
                      {b.level ? <span className="ml-1 text-amber-700 dark:text-amber-300">{t('（第 {n} 次）', { n: b.level + 1 })}</span> : null}
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-xs text-slate-500">{since(b.blockedAt, t)}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-xs">
                      {b.status === 'active' ? (
                        <span className="text-red-600">{t('封鎖中，{at}解除', { at: new Date(b.expiresAt).toLocaleString() })}</span>
                      ) : (
                        <span className="text-slate-500">{t('已解除')}</span>
                      )}
                    </td>
                    <td className="px-2 py-1.5 text-right">
                      {b.status === 'active' ? (
                        <button type="button" className={SMALL} disabled={pending} onClick={() => act(() => send(`/api/v1/admin/response/blocks/${b.id}/unblock`, 'POST'), t('已送出解除'))}>
                          {t('立即解除')}
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-slate-500">{t('還沒有自動封鎖過。')}</p>
        )}
        {active.length ? <p className="mt-2 text-xs text-slate-500">{t('封鎖中 {n} 筆', { n: active.length })}</p> : null}
      </section>

      <section className={BOX}>
        <h2 className="mb-3 font-semibold">{t('規則')}</h2>
        {view.rules.length ? (
          <ul className="mb-4 divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {view.rules.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-2 py-2">
                <span className="font-medium">{r.name}</span>
                <span className="rounded bg-red-50 px-1.5 py-0.5 text-xs text-red-800 dark:bg-red-950/50 dark:text-red-300">{triggerLabel(t, r.trigger)}</span>
                {r.trigger === 'bruteforce' ? <span className="text-xs text-slate-500">{t('失敗 {n} 次以上', { n: Number(r.params.threshold ?? 10) })}</span> : null}
                {r.trigger === 'finding' ? <span className="font-mono text-xs text-slate-500">{String(r.params.rule ?? '')}</span> : null}
                <span className="text-xs text-slate-500">
                  {t('封鎖 {m} 分鐘', { m: r.blockMinutes })}
                  {r.escalate ? t('（重複觸犯 ×6、×24）') : ''}
                </span>
                <span className="text-xs text-slate-500">{r.groupId ? t('群組：{g}', { g: groupName(r.groupId) }) : t('所有主機')}</span>
                {!r.enabled ? <span className="text-xs text-amber-700 dark:text-amber-300">{t('已停用')}</span> : null}
                <span className="ml-auto flex gap-1">
                  <button type="button" className={SMALL} disabled={pending} onClick={() => act(() => send(`/api/v1/admin/response/rules/${r.id}`, 'PUT', { enabled: !r.enabled }), r.enabled ? t('已停用') : t('已啟用'))}>
                    {r.enabled ? t('停用') : t('啟用')}
                  </button>
                  <button
                    type="button"
                    className={DANGER}
                    disabled={pending}
                    onClick={() => window.confirm(t('刪除規則「{name}」？', { name: r.name })) && act(() => send(`/api/v1/admin/response/rules/${r.id}`, 'DELETE'), t('已刪除'))}
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
              <input className={INPUT} value={rule.name} onChange={(e) => setRule({ ...rule, name: e.target.value })} placeholder={t('例：封鎖暴力破解來源')} />
            </Field>
            <Field label={t('觸發條件')} hint={triggerHint(t, rule.trigger)}>
              <select className={INPUT} value={rule.trigger} onChange={(e) => setRule({ ...rule, trigger: e.target.value as Trigger })}>
                {TRIGGERS.map((k) => (
                  <option key={k} value={k}>
                    {triggerLabel(t, k)}
                  </option>
                ))}
              </select>
            </Field>
            {rule.trigger === 'bruteforce' ? (
              <Field label={t('失敗次數門檻')}>
                <input className={INPUT} type="number" min={3} value={rule.threshold} onChange={(e) => setRule({ ...rule, threshold: e.target.value })} />
              </Field>
            ) : rule.trigger === 'finding' ? (
              <Field label={t('問題規則（可 * 結尾）')}>
                <input className={`${INPUT} font-mono`} value={rule.pattern} onChange={(e) => setRule({ ...rule, pattern: e.target.value })} />
              </Field>
            ) : (
              <span />
            )}
            <Field label={t('封鎖幾分鐘')} hint={t('勾選「重複觸犯加長」時，30 天內第二次 ×6、第三次以後 ×24')}>
              <input className={INPUT} type="number" min={5} value={rule.blockMinutes} onChange={(e) => setRule({ ...rule, blockMinutes: e.target.value })} />
            </Field>
            <Field label={t('套用到')}>
              <select className={INPUT} value={rule.groupId} onChange={(e) => setRule({ ...rule, groupId: e.target.value })}>
                <option value="">{t('所有主機')}</option>
                {view.groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </Field>
            <label className="flex items-center gap-2 self-end pb-1 text-sm">
              <input type="checkbox" checked={rule.escalate} onChange={(e) => setRule({ ...rule, escalate: e.target.checked })} />
              {t('重複觸犯加長')}
            </label>
          </div>
          <button
            type="button"
            className={BTN}
            disabled={pending || !rule.name.trim()}
            onClick={() =>
              act(
                () =>
                  send('/api/v1/admin/response/rules', 'POST', {
                    name: rule.name.trim(),
                    trigger: rule.trigger,
                    params: rule.trigger === 'bruteforce' ? { threshold: Number(rule.threshold) || 10 } : rule.trigger === 'finding' ? { rule: rule.pattern.trim() } : {},
                    blockMinutes: Number(rule.blockMinutes) || 60,
                    escalate: rule.escalate,
                    groupId: rule.groupId || null,
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
        <h2 className="mb-1 font-semibold">{t('主機群組')}</h2>
        <p className="mb-3 text-xs text-slate-500">{t('把主機分組（例：伺服器、門市電腦），規則可以只套用到某一組。')}</p>
        {view.groups.length ? (
          <ul className="mb-4 divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {view.groups.map((g) => (
              <li key={g.id} className="flex flex-wrap items-center gap-2 py-2">
                <span className="font-medium">{g.name}</span>
                <span className="text-xs text-slate-500">
                  {g.members.length
                    ? g.members.map((m) => view.hosts.find((h) => h.id === m)?.hostname ?? m).join('、')
                    : t('（沒有主機）')}
                </span>
                {Object.keys(g.config ?? {}).length ? (
                  <span className="rounded bg-teal-50 px-1.5 py-0.5 text-xs text-teal-800 dark:bg-teal-950/50 dark:text-teal-300" title={JSON.stringify(g.config)}>
                    {t('集中設定 {n} 項', { n: Object.keys(g.config).length })}
                  </span>
                ) : null}
                <span className="ml-auto flex gap-1">
                  <button type="button" className={SMALL} disabled={pending} onClick={() => setGroup(groupForm(g))}>
                    {t('修改')}
                  </button>
                  <button
                    type="button"
                    className={DANGER}
                    disabled={pending}
                    onClick={() => window.confirm(t('刪除群組「{name}」？只套用到它的規則會被停用。', { name: g.name })) && act(() => send(`/api/v1/admin/groups/${g.id}`, 'DELETE'), t('已刪除'))}
                  >
                    {t('刪除')}
                  </button>
                </span>
              </li>
            ))}
          </ul>
        ) : null}
        <div className="space-y-2 rounded-lg border border-dashed border-slate-300 p-3 dark:border-slate-700">
          <h3 className="text-sm font-medium">{group.id ? t('修改群組') : t('新增群組')}</h3>
          <Field label={t('名稱')}>
            <input className={INPUT} value={group.name} onChange={(e) => setGroup({ ...group, name: e.target.value })} placeholder={t('例：伺服器')} />
          </Field>
          <fieldset className="flex flex-wrap gap-3 text-sm">
            <legend className="mb-1 text-xs text-slate-500">{t('成員')}</legend>
            {view.hosts.map((h) => (
              <label key={h.id} className="flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={group.members.includes(h.id)}
                  onChange={(e) => setGroup({ ...group, members: e.target.checked ? [...group.members, h.id] : group.members.filter((x) => x !== h.id) })}
                />
                {h.hostname}
              </label>
            ))}
          </fieldset>
          <fieldset className="space-y-2 rounded-lg bg-slate-50 p-3 dark:bg-slate-800/50">
            <legend className="flex items-center text-xs font-medium text-slate-600 dark:text-slate-300">
              {t('集中設定（推給這組主機）')}
              <Hint text={t('留空＝不推，用那台電腦自己的設定。只能推這幾項安全的選項；效能蒐集、遠端動作只能在那台電腦上自己開。主機可以用 config set central_config false 拒收。設定用 Hub 的身分簽章，主機驗章後才套用。')} />
            </legend>
            <div className="grid gap-2 sm:grid-cols-4">
              <Field label={t('完整掃描間隔')} hint={t('例 30m、2h；最短 5 分鐘')}>
                <input className={INPUT} value={group.scan_interval} onChange={(e) => setGroup({ ...group, scan_interval: e.target.value })} placeholder="10m" />
              </Field>
              <Field label={t('連線快照間隔')} hint={t('例 1m、5m；最短 30 秒')}>
                <input className={INPUT} value={group.snapshot_interval} onChange={(e) => setGroup({ ...group, snapshot_interval: e.target.value })} placeholder="1m" />
              </Field>
              <Field label={t('檔案與開機自啟監控')}>
                <select className={INPUT} value={group.fim_enabled} onChange={(e) => setGroup({ ...group, fim_enabled: e.target.value })}>
                  <option value="">{t('不推（用主機自己的）')}</option>
                  <option value="true">{t('開啟')}</option>
                  <option value="false">{t('關閉')}</option>
                </select>
              </Field>
              <Field label={t('快照附上網域名稱')}>
                <select className={INPUT} value={group.dns_names} onChange={(e) => setGroup({ ...group, dns_names: e.target.value })}>
                  <option value="">{t('不推（用主機自己的）')}</option>
                  <option value="true">{t('開啟')}</option>
                  <option value="false">{t('關閉')}</option>
                </select>
              </Field>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              <Field label={t('額外監看的路徑（一行一個）')}>
                <textarea className={`${INPUT} font-mono`} rows={2} value={group.fim_extra_paths} onChange={(e) => setGroup({ ...group, fim_extra_paths: e.target.value })} />
              </Field>
              <Field label={t('不監看的路徑（一行一個，可用 *）')}>
                <textarea className={`${INPUT} font-mono`} rows={2} value={group.fim_ignore} onChange={(e) => setGroup({ ...group, fim_ignore: e.target.value })} />
              </Field>
            </div>
          </fieldset>
          <div className="flex gap-2">
            <button
              type="button"
              className={BTN}
              disabled={pending || !group.name.trim()}
              onClick={() =>
                act(
                  () =>
                    group.id
                      ? send(`/api/v1/admin/groups/${group.id}`, 'PUT', { name: group.name.trim(), members: group.members, config: centralOf(group) })
                      : send('/api/v1/admin/groups', 'POST', { name: group.name.trim(), members: group.members, config: centralOf(group) }),
                  t('已儲存'),
                  () => setGroup(EMPTY_GROUP),
                )
              }
            >
              {group.id ? t('儲存') : t('新增群組')}
            </button>
            {group.id ? (
              <button type="button" className={SMALL} onClick={() => setGroup(EMPTY_GROUP)}>
                {t('取消')}
              </button>
            ) : null}
          </div>
        </div>
      </section>
    </div>
  );
}
