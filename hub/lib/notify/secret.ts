// 通知頻道裡的祕密（SMTP 密碼、webhook 網址、HMAC 金鑰）加密存放：AES-256-GCM。
// 金鑰：環境變數 AI_SECURITY_MONITOR_HUB_SECRETS_KEY（64 個 hex 或 base64 的 32 bytes）優先；沒設就第一次用時產生一把存在 settings。
// 只擋「資料庫備份外流」這種情況；有資料庫完整權限的人仍拿得到 settings 裡的金鑰，所以正式環境建議設環境變數。
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { settings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { readEnv } from '@/lib/env';

const KEY_SETTING = 'notify.secret_key';
const PREFIX = 'enc:v1:';

function parseKey(raw: string): Buffer | null {
  const s = raw.trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return Buffer.from(s, 'hex');
  try {
    const b = Buffer.from(s, 'base64');
    return b.length === 32 ? b : null;
  } catch {
    return null;
  }
}

let cached: Buffer | null = null;

export function resetSecretKeyForTests(): void {
  cached = null;
}

export async function secretKey(db: DB): Promise<Buffer> {
  if (cached) return cached;
  const fromEnv = readEnv('ASA_HUB_SECRETS_KEY');
  if (fromEnv) {
    const k = parseKey(fromEnv);
    if (!k) throw new Error('AI_SECURITY_MONITOR_HUB_SECRETS_KEY must be 32 bytes (64 hex chars or base64)');
    cached = k;
    return k;
  }
  const [row] = await db.select().from(settings).where(eq(settings.key, KEY_SETTING)).limit(1);
  const saved = typeof row?.value === 'string' ? parseKey(row.value) : null;
  if (saved) {
    cached = saved;
    return saved;
  }
  const k = randomBytes(32);
  // 兩個行程同時產生時以先寫入的為準
  await db.insert(settings).values({ key: KEY_SETTING, value: k.toString('base64'), updatedBy: 'system' }).onConflictDoNothing();
  const [again] = await db.select().from(settings).where(eq(settings.key, KEY_SETTING)).limit(1);
  cached = parseKey(String(again?.value ?? '')) ?? k;
  return cached;
}

export function isEncrypted(v: unknown): v is string {
  return typeof v === 'string' && v.startsWith(PREFIX);
}

export function encrypt(key: Buffer, plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return `${PREFIX}${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${ct.toString('base64')}`;
}

export function decrypt(key: Buffer, value: string): string {
  if (!isEncrypted(value)) return value;
  const [iv, tag, ct] = value.slice(PREFIX.length).split(':');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
}
