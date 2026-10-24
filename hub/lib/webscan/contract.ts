// Hub ↔ webscan runner 的格式（contract/webscan-*.v1.json；Rust 端是 agent/src/webscan，兩邊的測試都驗同一份檔案）。
import net from 'node:net';
import { z } from 'zod';
import { WEBSCAN_PROFILES, WEBSCAN_SCANNERS, WEBSCAN_VERIFY_METHODS } from './scanners';

const ip = z.string().max(64).refine((s) => net.isIP(s) > 0, 'ip');

/** runner 認領工作：`POST /api/v1/webscan/jobs/claim`。 */
export const ClaimRequest = z
  .object({
    version: z.string().max(40).default(''),
    hostname: z.string().max(255).default(''),
    capabilities: z
      .array(
        z
          .object({
            scanner: z.string().max(40),
            version: z.string().max(80).default(''),
            templates: z.string().max(80).optional(),
          })
          .passthrough(),
      )
      .max(32)
      .default([]),
    max_jobs: z.number().int().min(1).max(4).default(1),
    self_ips: z.array(ip).max(64).default([]),
  })
  .passthrough();
export type ClaimRequestT = z.infer<typeof ClaimRequest>;

export const HeartbeatBody = z
  .object({
    step: z.string().max(40).optional(),
    message: z.string().max(300).optional(),
    progress: z.number().min(0).max(1).optional(),
  })
  .passthrough();
export type HeartbeatBodyT = z.infer<typeof HeartbeatBody>;

export const StepResult = z
  .object({
    scanner: z.string().max(40),
    ok: z.boolean(),
    exit_code: z.number().int().nullable().default(null),
    duration_ms: z.number().int().min(0).nullable().default(null),
    error: z.string().max(500).nullable().default(null),
  })
  .passthrough();

export const ResultBody = z
  .object({
    ok: z.boolean(),
    error: z.string().max(500).nullable().default(null),
    steps: z.array(StepResult).max(32).default([]),
    verify: z
      .object({
        found: z.boolean(),
        http_status: z.number().int().nullable().default(null),
        detail: z.string().max(500).default(''),
      })
      .passthrough()
      .nullable()
      .default(null),
  })
  .passthrough();
export type ResultBodyT = z.infer<typeof ResultBody>;

/** 每個掃描器的選項（runner 端以同樣的白名單、serde deny_unknown_fields 檢查）。 */
export const NucleiOptions = z
  .object({
    exclude_tags: z.array(z.enum(['intrusive', 'dos', 'fuzz'])).min(1),
    severities: z.array(z.enum(['info', 'low', 'medium', 'high', 'critical'])).min(1),
  })
  .strict();
export const TestsslOptions = z.object({ fast: z.boolean() }).strict();
export const EmptyOptions = z.object({}).strict();

export const JobStep = z.discriminatedUnion('scanner', [
  z.object({ scanner: z.literal('httpx'), options: EmptyOptions }).strict(),
  z.object({ scanner: z.literal('tlsx'), options: EmptyOptions }).strict(),
  z.object({ scanner: z.literal('nuclei'), options: NucleiOptions }).strict(),
  z.object({ scanner: z.literal('testssl'), options: TestsslOptions }).strict(),
]);
export type JobStepT = z.infer<typeof JobStep>;

/** 交給 runner 的工作內容（claim 回應裡的每一個 job）。 */
export const JobSpec = z
  .object({
    id: z.string().regex(/^wsj_[0-9a-f]{16}$/),
    kind: z.enum(['scan', 'verify']),
    profile: z.enum(WEBSCAN_PROFILES),
    lease_ms: z.number().int().positive(),
    deadline: z.string().datetime({ offset: true }),
    target: z
      .object({
        id: z.string().regex(/^wt_[0-9a-f]{16}$/),
        url: z.string().max(2048),
        scheme: z.enum(['http', 'https']),
        host: z.string().max(253),
        port: z.number().int().min(1).max(65535),
        path: z.string().max(512),
        pinned_ips: z.array(ip).min(1).max(16),
        internal: z.boolean(),
      })
      .strict(),
    scope: z
      .object({
        hosts: z.array(z.string().max(253)).min(1).max(16),
        allowed_private_cidrs: z.array(z.string().max(64)).max(64),
      })
      .strict(),
    limits: z
      .object({
        timeout_ms: z.number().int().positive(),
        rate_per_sec: z.number().int().min(1).max(50),
        concurrency: z.number().int().min(1).max(10),
        max_output_bytes: z.number().int().positive(),
      })
      .strict(),
    steps: z.array(JobStep).max(WEBSCAN_SCANNERS.length),
    verify: z
      .object({ method: z.enum(WEBSCAN_VERIFY_METHODS.filter((m) => m !== 'dns-txt') as ['well-known', 'meta']), token: z.string().regex(/^asm-verify-[0-9a-f]{32}$/) })
      .strict()
      .nullable(),
  })
  .strict();
export type JobSpecT = z.infer<typeof JobSpec>;

export const ClaimResponse = z.object({ jobs: z.array(JobSpec), poll_after_ms: z.number().int().positive(), server_time: z.string() }).strict();

/** artifact 上傳的 query string（body 是工具原始輸出）。 */
export const ArtifactMeta = z.object({
  scanner: z.enum(WEBSCAN_SCANNERS),
  format: z.enum(['jsonl', 'json', 'txt']),
  exit_code: z.coerce.number().int().nullable().default(null),
  duration_ms: z.coerce.number().int().min(0).nullable().default(null),
  truncated: z.enum(['0', '1', 'true', 'false']).default('0').transform((v) => v === '1' || v === 'true'),
});
export type ArtifactMetaT = z.infer<typeof ArtifactMeta>;
