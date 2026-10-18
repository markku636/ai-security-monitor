// 集中設定：主機群組可以推一小組「安全的」設定給成員（掃描／快照間隔、檔案完整性監控、快照附網域）。
// 不推：效能蒐集（只能那台電腦自己開）、遠端動作、Hub 設定、任何指令。
// 一台主機屬於多個群組時依群組名稱排序合併：單一值後面的蓋前面、清單取聯集。
// 送給 agent 時用 Hub 的 Ed25519 身分簽章；agent 用加入時釘選的公鑰驗章，對不上就不套用。
import crypto from 'node:crypto';
import { asc, eq } from 'drizzle-orm';
import { z } from 'zod';
import { agentGroupMembers, agentGroups } from '@/drizzle/schema';
import { canonical } from '@/lib/actions/sign';
import type { DB } from '@/lib/db';
import { hubIdentity, sign } from '@/lib/enroll/identity';

/** humantime 的子集：數字＋s／m／h。 */
const duration = (minSeconds: number) =>
  z
    .string()
    .trim()
    .regex(/^\d{1,5}[smh]$/)
    .refine((v) => seconds(v) >= minSeconds && seconds(v) <= 7 * 86_400, { message: 'out_of_range' });

export function seconds(v: string): number {
  const n = Number(v.slice(0, -1));
  return v.endsWith('h') ? n * 3600 : v.endsWith('m') ? n * 60 : n;
}

const path = z.string().trim().min(1).max(260);

export const CentralConfig = z
  .object({
    /** 完整掃描間隔（最短 5 分鐘）。 */
    scan_interval: duration(300),
    /** 連線快照間隔（最短 30 秒）。 */
    snapshot_interval: duration(30),
    /** 快照附上連線 IP 對應的網域。 */
    dns_names: z.boolean(),
    fim_enabled: z.boolean(),
    fim_extra_paths: z.array(path).max(50),
    fim_ignore: z.array(path).max(100),
  })
  .partial()
  .strict();
export type CentralConfigT = z.infer<typeof CentralConfig>;

const LIST_KEYS = ['fim_extra_paths', 'fim_ignore'] as const;

/** 合併多個群組的設定（順序＝群組名稱）。 */
export function mergeConfigs(list: CentralConfigT[]): CentralConfigT {
  const out: Record<string, unknown> = {};
  for (const c of list) {
    for (const [k, v] of Object.entries(c)) {
      if (v === undefined) continue;
      if ((LIST_KEYS as readonly string[]).includes(k)) {
        const prev = (out[k] as string[] | undefined) ?? [];
        out[k] = [...prev, ...(v as string[]).filter((x) => !prev.includes(x))];
      } else out[k] = v;
    }
  }
  return out as CentralConfigT;
}

export interface Effective {
  /** 設定內容的版本（sha256 前 16 個 hex）；沒有任何集中設定時是 null。 */
  version: string | null;
  config: CentralConfigT;
  groups: string[];
}

export async function effectiveConfig(db: DB, agentId: string): Promise<Effective> {
  const rows = await db
    .select({ name: agentGroups.name, config: agentGroups.config })
    .from(agentGroupMembers)
    .innerJoin(agentGroups, eq(agentGroups.id, agentGroupMembers.groupId))
    .where(eq(agentGroupMembers.agentId, agentId))
    .orderBy(asc(agentGroups.name), asc(agentGroups.id));
  const parsed = rows.map((r) => CentralConfig.safeParse(r.config ?? {})).map((p) => (p.success ? p.data : {}));
  const config = mergeConfigs(parsed);
  const json = canonical(config);
  return {
    version: Object.keys(config).length ? crypto.createHash('sha256').update(json).digest('hex').slice(0, 16) : null,
    config,
    groups: rows.map((r) => r.name),
  };
}

/** 簽章的內容：用途、agent、版本、設定 JSON（agent 驗章後直接解析這段 JSON，不用自己重排）。 */
export function configMessage(agentId: string, version: string, configJson: string): string {
  return `aism-central-config-v1\n${agentId}\n${version}\n${configJson}`;
}

export async function signedConfig(db: DB, agentId: string) {
  const e = await effectiveConfig(db, agentId);
  if (!e.version) return { version: null, groups: e.groups };
  const configJson = canonical(e.config);
  const id = await hubIdentity(db);
  return {
    version: e.version,
    config_json: configJson,
    groups: e.groups,
    signature: sign(id, configMessage(agentId, e.version, configJson)),
  };
}
