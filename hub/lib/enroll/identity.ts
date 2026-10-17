// Hub 身分（Ed25519）：第一次用到時產生並存進 settings（hub_identity），之後重啟沿用。
// 指紋＝base32(SHA-256(原始公鑰)) 前 20 字、每 4 字一組；電腦端第一次連上時記下（TOFU），之後不符就拒絕。
// 格式規則必須與 agent 端一致（contract/hub-identity.v1.json、enroll-status.v1.json 兩邊都測）。
import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { settings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { env, readEnv } from '@/lib/env';

const SETTING_KEY = 'hub_identity';
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** Ed25519 PKCS8 DER 的固定前綴（後面接 32 bytes seed）。 */
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** RFC 4648 base32（A-Z2-7，不補 =）。 */
export function base32(buf: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of buf) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function groups(s: string): string {
  return s.match(/.{1,4}/g)!.join('-');
}

/** 指紋：`XXXX-XXXX-XXXX-XXXX-XXXX`。 */
export function fingerprintOf(rawPublicKey: Uint8Array): string {
  return groups(base32(crypto.createHash('sha256').update(rawPublicKey).digest()).slice(0, 20));
}

/** 申請碼（電腦端也會顯示同一組，讓管理員對照）：`XXXX-XXXX`。 */
export function requestCodeOf(requestSecret: string): string {
  return groups(base32(crypto.createHash('sha256').update(`asa-enroll-code|${requestSecret}`, 'utf8').digest()).slice(0, 8));
}

export const FINGERPRINT_RE = /^[A-Z2-7]{4}(-[A-Z2-7]{4}){4}$/;

export function identityMessage(nonce: string, fingerprint: string): string {
  return `asa-hub-identity|v1|${nonce}|${fingerprint}`;
}

export function approvalMessage(requestId: string, agentId: string, clientKey: string): string {
  return `asa-enroll-approved|v1|${requestId}|${agentId}|${crypto.createHash('sha256').update(clientKey).digest('hex')}`;
}

export interface HubIdentity {
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
  /** 原始 32 bytes 公鑰（base64url）。 */
  publicKeyB64: string;
  fingerprint: string;
}

function rawPublic(pub: crypto.KeyObject): Buffer {
  return pub.export({ format: 'der', type: 'spki' }).subarray(-32);
}

/** 從 PKCS8 DER 建身分（測試用的固定 seed 也走這裡）。 */
export function identityFromPkcs8(der: Buffer): HubIdentity {
  const privateKey = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const publicKey = crypto.createPublicKey(privateKey);
  const raw = rawPublic(publicKey);
  return { publicKey, privateKey, publicKeyB64: raw.toString('base64url'), fingerprint: fingerprintOf(raw) };
}

/** 32 bytes seed → PKCS8 DER。 */
export function pkcs8FromSeed(seed: Buffer): Buffer {
  if (seed.length !== 32) throw new Error('ed25519 seed must be 32 bytes');
  return Buffer.concat([PKCS8_PREFIX, seed]);
}

/** 原始公鑰（base64url）驗 Ed25519 簽章。 */
export function verifyWithRawKey(publicKeyB64: string, message: string, signatureB64: string): boolean {
  try {
    const raw = Buffer.from(publicKeyB64, 'base64url');
    if (raw.length !== 32) return false;
    const key = crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(message, 'utf8'), key, Buffer.from(signatureB64, 'base64url'));
  } catch {
    return false;
  }
}

export function sign(id: HubIdentity, message: string): string {
  return crypto.sign(null, Buffer.from(message, 'utf8'), id.privateKey).toString('base64url');
}

const g = globalThis as unknown as { __asaHubIdentity?: HubIdentity };

function parseStored(v: unknown): HubIdentity | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as { public_key?: unknown; private_key?: unknown };
  if (typeof o.private_key !== 'string') return null;
  try {
    const id = identityFromPkcs8(Buffer.from(o.private_key, 'base64url'));
    // 存的公鑰跟私鑰算出來的不同 → 資料壞了，不用（避免指紋悄悄變掉）
    if (typeof o.public_key === 'string' && o.public_key !== id.publicKeyB64) return null;
    return id;
  } catch {
    return null;
  }
}

export class HubIdentityCorrupt extends Error {}

/** Hub 身分：settings 有就用，沒有就產生一組（兩個請求同時產生時以先寫入的為準）。 */
export async function hubIdentity(db: DB): Promise<HubIdentity> {
  if (g.__asaHubIdentity) return g.__asaHubIdentity;
  const read = async () => (await db.select().from(settings).where(eq(settings.key, SETTING_KEY)).limit(1))[0];
  let row = await read();
  if (!row) {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const der = privateKey.export({ format: 'der', type: 'pkcs8' });
    const fresh = identityFromPkcs8(der);
    await db
      .insert(settings)
      .values({ key: SETTING_KEY, value: { public_key: fresh.publicKeyB64, private_key: der.toString('base64url') }, updatedBy: 'system' })
      .onConflictDoNothing();
    row = await read();
  }
  const id = parseStored(row?.value);
  if (!id) throw new HubIdentityCorrupt('settings.hub_identity is unreadable; refusing to replace it silently');
  g.__asaHubIdentity = id;
  return id;
}

export function resetHubIdentityForTests(): void {
  g.__asaHubIdentity = undefined;
}

export function hubName(): string {
  return (readEnv('ASA_HUB_NAME') || 'Security Hub').slice(0, 100);
}

/** 免金鑰加入申請：預設開；ASA_HUB_ENROLL_REQUESTS=0/false/off 關。 */
export function keylessEnabled(): boolean {
  return !['0', 'false', 'off', 'no'].includes(readEnv('ASA_HUB_ENROLL_REQUESTS').toLowerCase());
}

export function hubInfo(id: HubIdentity) {
  const e = env();
  return { name: hubName(), version: e.version, fingerprint: id.fingerprint };
}
