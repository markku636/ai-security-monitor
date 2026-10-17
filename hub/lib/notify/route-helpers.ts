// 通知管理 API 的共用：讀 body、把驗證錯誤轉成 400、寫稽核。
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiWrite } from '@/lib/auth/api';
import { BodyTooLarge, error, readJson, sourceIp } from '@/lib/http';
import { NotifyInputError } from './admin';

type Handler = (body: unknown, actor: string) => Promise<Response>;

/** 管理員寫入：讀 JSON（最多 32 KB）、執行、把輸入錯誤轉成 400。 */
export async function notifyWrite(req: Request, fn: Handler, opts: { body?: boolean } = { body: true }): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: unknown = {};
  if (opts.body !== false) {
    try {
      body = await readJson(req, 32 * 1024);
    } catch (e) {
      return error(e instanceof BodyTooLarge ? 413 : 400, 'bad_request');
    }
  }
  try {
    return await fn(body, actorOf(id));
  } catch (e) {
    if (e instanceof NotifyInputError) return error(e.code.startsWith('too_many') ? 409 : 400, e.code);
    if (e instanceof z.ZodError) return error(400, 'bad_request', { field: e.issues[0]?.path.join('.') });
    throw e;
  }
}

export async function notifyAudit(req: Request, actor: string, action: string, targetId: string, details: Record<string, unknown> = {}): Promise<void> {
  await audit({ actor, actorRole: 'admin', action, targetType: 'notification', targetId, sourceIp: sourceIp(req), details });
}
