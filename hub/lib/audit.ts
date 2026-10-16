import { auditLog } from '@/drizzle/schema';
import { getDb } from '@/lib/db';

export interface AuditEntry {
  actor: string;
  actorRole: string;
  action: string;
  targetType?: string;
  targetId?: string;
  sourceIp?: string;
  details?: Record<string, unknown>;
}

/** 稽核紀錄；寫失敗只記 log，不影響主流程。 */
export async function audit(e: AuditEntry): Promise<void> {
  try {
    await getDb()
      .insert(auditLog)
      .values({
        actor: e.actor,
        actorRole: e.actorRole,
        action: e.action,
        targetType: e.targetType ?? null,
        targetId: e.targetId ?? null,
        sourceIp: e.sourceIp ?? null,
        details: e.details ?? null,
      });
  } catch (err) {
    console.error('[audit] failed', err);
  }
}
