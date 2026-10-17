// 遠端動作簽章：hub 簽署金鑰 → 每個 agent 的 action_key（HMAC 衍生）→ 每個動作的 token。
// agent 只拿到自己的 action_key（註冊時），用它驗 token。設了 ASA_HUB_ACTION_SIGNING_KEY 時資料庫裡沒有能偽造 token 的東西。
// canonical JSON 的規則必須與 agent/src/hub/actions.rs 一致（contract/action.v1.json 兩邊都測）。
import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { settings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { readEnv } from '@/lib/env';

const SETTING_KEY = 'action_signing_key';

/** 物件 key 排序、無空白的 JSON（陣列保持原順序；key 只用 ASCII，兩邊排序才一致）。 */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
    .join(',')}}`;
}

function hmacHex(key: string, msg: string): string {
  return crypto.createHmac('sha256', key).update(msg).digest('hex');
}

export function actionKeyFor(signingKey: string, agentId: string): string {
  return hmacHex(signingKey, `asa-action-key|${agentId}`);
}

export interface SignedFields {
  action_id: string;
  agent_id: string;
  kind: string;
  params: Record<string, unknown>;
  expires_at: string;
}

export function tokenFor(actionKey: string, f: SignedFields): string {
  return hmacHex(actionKey, canonical(f));
}

export function paramsHash(params: Record<string, unknown>): string {
  return crypto.createHash('sha256').update(canonical(params)).digest('hex').slice(0, 32);
}

const g = globalThis as unknown as { __asaSigningKey?: string };

/**
 * 簽署金鑰：`AI_SECURITY_MONITOR_HUB_ACTION_SIGNING_KEY`（舊名 `ASA_HUB_ACTION_SIGNING_KEY`，皆可 _FILE）優先；沒設就第一次用到時隨機產生並存進 settings 表，
 * 之後重啟沿用（換掉＝所有 agent 要重新註冊才拿得到新的 action_key）。
 */
export async function signingKey(db: DB): Promise<string> {
  const fromEnv = readEnv('ASA_HUB_ACTION_SIGNING_KEY');
  if (fromEnv) return fromEnv;
  if (g.__asaSigningKey) return g.__asaSigningKey;
  const rows = await db.select().from(settings).where(eq(settings.key, SETTING_KEY)).limit(1);
  let key = typeof rows[0]?.value === 'string' ? (rows[0].value as string) : '';
  if (!key) {
    key = crypto.randomBytes(32).toString('hex');
    await db.insert(settings).values({ key: SETTING_KEY, value: key, updatedBy: 'system' }).onConflictDoNothing();
    // 兩個請求同時產生時以先寫入的為準。
    const again = await db.select().from(settings).where(eq(settings.key, SETTING_KEY)).limit(1);
    key = String(again[0]?.value ?? key);
  }
  g.__asaSigningKey = key;
  return key;
}

export function resetSigningKeyForTests(): void {
  g.__asaSigningKey = undefined;
}
