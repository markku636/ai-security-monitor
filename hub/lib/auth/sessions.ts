// 管理員 session：cookie 存隨機 token，資料庫只存 sha256。指紋綁管理員金鑰 → 換金鑰即全部登出。
import { and, eq, gt, lt } from 'drizzle-orm';
import { sessions } from '@/drizzle/schema';
import { getDb } from '@/lib/db';
import { env, keycloakLoginEnabled, readEnv } from '@/lib/env';
import { randomToken, sha256Hex } from './crypto';

export const SESSION_COOKIE = 'asa_admin';
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const TOUCH_EVERY_MS = 60 * 1000;

export function secretFingerprint(): string {
  return sha256Hex(
    `asa-hub-session:${env().adminSecret}:${keycloakLoginEnabled() ? readEnv('ASA_HUB_KEYCLOAK_ISSUER') : ''}:${readEnv('ASA_HUB_KEYCLOAK_CLIENT_ID')}:${readEnv('ASA_HUB_KEYCLOAK_CLIENT_SECRET')}:${readEnv('ASA_HUB_KEYCLOAK_ALLOWED_EMAILS')}:${readEnv('ASA_HUB_KEYCLOAK_ONLY')}:${readEnv('ASA_HUB_GOOGLE_CLIENT_ID')}:${readEnv('ASA_HUB_GOOGLE_CLIENT_SECRET')}:${readEnv('ASA_HUB_GOOGLE_ALLOWED_EMAILS')}:${readEnv('ASA_HUB_GOOGLE_ONLY')}`,
  );
}

export async function createSession(ip: string): Promise<{ token: string; expiresAt: Date }> {
  const token = randomToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await getDb().insert(sessions).values({
    tokenHash: sha256Hex(token),
    secretFingerprint: secretFingerprint(),
    sourceIp: ip,
    expiresAt,
  });
  return { token, expiresAt };
}

export async function validateSession(token: string | undefined): Promise<boolean> {
  if (!token || token.length > 200) return false;
  const db = getDb();
  const hash = sha256Hex(token);
  const rows = await db
    .select()
    .from(sessions)
    .where(and(eq(sessions.tokenHash, hash), gt(sessions.expiresAt, new Date())))
    .limit(1);
  const row = rows[0];
  if (!row || row.secretFingerprint !== secretFingerprint()) return false;
  if (Date.now() - row.lastSeenAt.getTime() > TOUCH_EVERY_MS) {
    await db.update(sessions).set({ lastSeenAt: new Date() }).where(eq(sessions.tokenHash, hash));
  }
  return true;
}

export async function deleteSession(token: string | undefined): Promise<void> {
  if (!token) return;
  await getDb().delete(sessions).where(eq(sessions.tokenHash, sha256Hex(token)));
}

export async function pruneSessions(): Promise<void> {
  await getDb().delete(sessions).where(lt(sessions.expiresAt, new Date()));
}

export function sessionCookie(token: string, maxAgeSec: number, secure: boolean): string {
  return [
    `${SESSION_COOKIE}=${token}`,
    'HttpOnly',
    // OAuth returns through a cross-site redirect; allow the session on its top-level GET.
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${maxAgeSec}`,
    secure ? 'Secure' : '',
  ]
    .filter(Boolean)
    .join('; ');
}
