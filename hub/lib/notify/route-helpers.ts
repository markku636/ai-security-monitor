// 通知管理 API 的共用（沿用 lib/admin-write）。
import { adminAudit, adminWrite } from '@/lib/admin-write';

export const notifyWrite = adminWrite;

export async function notifyAudit(req: Request, actor: string, action: string, targetId: string, details: Record<string, unknown> = {}): Promise<void> {
  await adminAudit(req, actor, action, 'notification', targetId, details);
}
