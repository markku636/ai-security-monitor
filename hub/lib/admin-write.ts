// 管理員寫入 API 的共用：讀 body、把輸入錯誤轉成 400／409、寫稽核。
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiWrite } from '@/lib/auth/api';
import { BodyTooLarge, error, readJson, sourceIp } from '@/lib/http';

/** 使用者輸入不合法（code 會原樣回給網頁）；`too_many_*` 回 409。 */
export class InputError extends Error {
  constructor(public code: string) {
    super(code);
  }
}

type Handler = (body: unknown, actor: string) => Promise<Response>;

export async function adminWrite(req: Request, fn: Handler, opts: { body?: boolean } = { body: true }): Promise<Response> {
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
    if (e instanceof InputError) return error(e.code.startsWith('too_many') ? 409 : 400, e.code);
    if (e instanceof z.ZodError) return error(400, 'bad_request', { field: e.issues[0]?.path.join('.') });
    throw e;
  }
}

export async function adminAudit(req: Request, actor: string, action: string, targetType: string, targetId: string, details: Record<string, unknown> = {}): Promise<void> {
  await audit({ actor, actorRole: 'admin', action, targetType, targetId, sourceIp: sourceIp(req), details });
}
