// 遠端動作的種類與參數驗證。hub 先擋明顯錯誤；agent 端還會再檢查（本機位址、白名單、已知良好、過寬網段）。
import net from 'node:net';
import { z } from 'zod';

export const ACTION_KINDS = ['block_ip', 'unblock_ip', 'close_port'] as const;
export type ActionKind = (typeof ACTION_KINDS)[number];

/** 單一 IP 或 CIDR；拒絕 loopback、未指定位址、多播與過寬網段（v4 < /10、v6 < /19，與 agent 同步情資的上限一致）。 */
export function checkTarget(s: string): string | null {
  const [addr, bits, extra] = s.split('/');
  if (extra !== undefined) return 'bad_target';
  const fam = net.isIP(addr);
  if (!fam) return 'bad_target';
  if (bits !== undefined) {
    if (!/^\d{1,3}$/.test(bits)) return 'bad_target';
    const n = Number(bits);
    if (n > (fam === 4 ? 32 : 128)) return 'bad_target';
    if (n < (fam === 4 ? 10 : 19)) return 'target_too_broad';
  }
  const a = addr.toLowerCase();
  if (fam === 4) {
    const first = Number(a.split('.')[0]);
    if (first === 127 || first === 0 || first >= 224) return 'target_reserved';
  } else if (a === '::1' || a === '::' || a.startsWith('ff')) {
    return 'target_reserved';
  }
  return null;
}

const Target = z
  .string()
  .max(64)
  .superRefine((s, ctx) => {
    const err = checkTarget(s.trim());
    if (err) ctx.addIssue({ code: 'custom', message: err });
  })
  .transform((s) => s.trim());

// agent 提案的 reason 可能是較長的證據鍵：截斷而不是拒絕。
const Reason = z
  .string()
  .max(500)
  .transform((s) => s.slice(0, 120))
  .optional();

/** 方向接受 agent 的別名（inbound／outbound），正規化成 in／out／both。 */
const Direction = z
  .enum(['in', 'out', 'both', 'inbound', 'outbound'])
  .transform((d) => (d === 'inbound' ? 'in' : d === 'outbound' ? 'out' : d))
  .default('both');

export const ParamsByKind = {
  block_ip: z.object({ ip: Target, direction: Direction, reason: Reason }).strict(),
  unblock_ip: z.object({ ip: Target }).strict(),
  close_port: z
    .object({ proto: z.enum(['tcp', 'udp']), port: z.number().int().min(1).max(65535), direction: z.literal('inbound').optional() })
    .strict(),
} satisfies Record<ActionKind, z.ZodTypeAny>;

export interface KindInfo {
  destructive: boolean;
  requiresElevation: boolean;
}

/** close_port 可能讓服務中斷 → 視為破壞性（核准時要輸入主機名稱確認）。 */
export const KIND_INFO: Record<ActionKind, KindInfo> = {
  block_ip: { destructive: false, requiresElevation: true },
  unblock_ip: { destructive: false, requiresElevation: true },
  close_port: { destructive: true, requiresElevation: true },
};

export type ParseResult = { ok: true; kind: ActionKind; params: Record<string, unknown> } | { ok: false; error: string };

export function parseAction(kind: string, params: unknown): ParseResult {
  if (!(ACTION_KINDS as readonly string[]).includes(kind)) return { ok: false, error: 'unknown_kind' };
  const k = kind as ActionKind;
  const r = ParamsByKind[k].safeParse(params);
  if (!r.success) {
    const issue = r.error.issues[0];
    return { ok: false, error: issue?.code === 'custom' && issue.message ? issue.message : 'bad_params' };
  }
  // 去掉 undefined 欄位，讓 canonical 與雜湊穩定。
  const clean = JSON.parse(JSON.stringify(r.data)) as Record<string, unknown>;
  return { ok: true, kind: k, params: clean };
}
