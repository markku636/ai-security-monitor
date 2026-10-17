// Hub 更新提示：每 6 小時查一次 GitHub 最新 Release（結果存在 settings），有新版就在管理員頁面顯示橫幅。
// ASA_HUB_UPDATE_CHECK=0 關閉（離線環境、測試）。
import { eq } from 'drizzle-orm';
import { settings } from '@/drizzle/schema';
import { getDb } from '@/lib/db';
import { env, readEnv } from '@/lib/env';

const KEY = 'update_check';
const EVERY_MS = 6 * 3600_000;
const API = 'https://api.github.com/repos/markku636/ai-security-monitor/releases/latest';

export interface UpdateInfo {
  checkedAt: string;
  latest: string | null;
  url: string | null;
  error?: string;
}

function enabled(): boolean {
  return readEnv('ASA_HUB_UPDATE_CHECK') !== '0' && process.env.NODE_ENV !== 'test';
}

/** a 比 b 新（數字段比較；-rc 之類視為較舊）。 */
export function newer(a: string, b: string): boolean {
  const parse = (v: string) => {
    const [main, pre] = v.replace(/^v/, '').split('-', 2);
    return { nums: main.split('.').map((x) => Number.parseInt(x, 10) || 0), pre: pre ?? null };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d) return d > 0;
  }
  if (x.pre && !y.pre) return false;
  if (!x.pre && y.pre) return true;
  return (x.pre ?? '') > (y.pre ?? '');
}

async function cached(): Promise<UpdateInfo | null> {
  const [row] = await getDb().select().from(settings).where(eq(settings.key, KEY)).limit(1);
  return (row?.value as UpdateInfo | undefined) ?? null;
}

let inflight: Promise<void> | null = null;

async function refresh(): Promise<void> {
  let info: UpdateInfo;
  try {
    const r = await fetch(API, { headers: { 'user-agent': `asa-hub/${env().version}`, accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(5000) });
    if (r.status === 404) {
      info = { checkedAt: new Date().toISOString(), latest: null, url: null };
    } else if (!r.ok) {
      info = { checkedAt: new Date().toISOString(), latest: null, url: null, error: `HTTP ${r.status}` };
    } else {
      const j = (await r.json()) as { tag_name?: string; html_url?: string };
      info = { checkedAt: new Date().toISOString(), latest: j.tag_name?.replace(/^v/, '') ?? null, url: j.html_url ?? null };
    }
  } catch (e) {
    info = { checkedAt: new Date().toISOString(), latest: null, url: null, error: (e as Error).message };
  }
  await getDb()
    .insert(settings)
    .values({ key: KEY, value: info, updatedBy: 'system' })
    .onConflictDoUpdate({ target: settings.key, set: { value: info, updatedAt: new Date(), updatedBy: 'system' } });
}

/** GitHub 上的最新版（讀快取；過期就在背景更新、不等，讓頁面不會被 GitHub 拖慢）。關閉檢查時回 null。 */
export async function latestRelease(): Promise<{ latest: string; url: string | null } | null> {
  if (!enabled()) return null;
  const c = await cached().catch(() => null);
  if (!c || Date.now() - Date.parse(c.checkedAt) > EVERY_MS) {
    inflight ??= refresh()
      .catch(() => undefined)
      .finally(() => {
        inflight = null;
      });
  }
  return c?.latest ? { latest: c.latest, url: c.url } : null;
}

/** Hub 本身有沒有新版。 */
export async function updateAvailable(): Promise<{ latest: string; url: string | null } | null> {
  const r = await latestRelease();
  return r && newer(r.latest, env().version) ? r : null;
}

/** agent 心跳回報的更新狀態（agents.update_info）。 */
export interface AgentUpdateLike {
  mode?: string | null;
  owner?: string | null;
  latest?: string | null;
}

/** 這台主機有沒有比它目前版本新的版本：看 agent 自己回報的，也看 Hub 查到的最新版，取較新的。沒有回 null。 */
export function agentNewVersion(version: string, info: AgentUpdateLike | null | undefined, hubLatest: string | null | undefined): string | null {
  if (!version) return null;
  const found = [info?.latest, hubLatest].filter((v): v is string => !!v && newer(v, version));
  if (!found.length) return null;
  return found.reduce((a, b) => (newer(b, a) ? b : a));
}
