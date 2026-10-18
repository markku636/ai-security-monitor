// 頁面（server component）用的身分檢查。API route 用 access.ts 的 identify(req)。
import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { identifyByCredentials, type Identity } from './access';
import { SESSION_COOKIE } from './sessions';

export async function getViewer(): Promise<Identity> {
  const c = await cookies();
  const h = await headers();
  const auth = h.get('authorization') ?? '';
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  return identifyByCredentials(m?.[1], c.get(SESSION_COOKIE)?.value, h.get('host'));
}

/** 未登入就導到 /login。 */
export async function requireViewer(): Promise<Identity> {
  const id = await getViewer();
  if (id.role !== 'admin' && id.role !== 'viewer') redirect('/login');
  return id;
}

export async function requireAdmin(): Promise<Identity> {
  const id = await getViewer();
  if (id.role !== 'admin') redirect('/login');
  return id;
}
