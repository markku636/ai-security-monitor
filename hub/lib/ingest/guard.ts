// 上傳防護（沿用 open-token-monitor 的 ingestGuard 觀念）：壓縮前後大小上限、JSON 結構上限、禁止的 key。
// 違規一律 400／413，只回規則名，不回 payload 內容。
import zlib from 'node:zlib';
import { BodyTooLarge, readBytes } from '@/lib/http';

export const LIMITS = Object.freeze({
  compressedBytes: 4 * 1024 * 1024,
  decompressedBytes: 24 * 1024 * 1024,
  depth: 24,
  stringLength: 16_384,
  arrayLength: 5_000,
  objectKeys: 2_000,
  keyLength: 256,
  nodes: 500_000,
  magnitude: 1e15,
});

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export class IngestRejected extends Error {
  constructor(
    public readonly status: number,
    public readonly rule: string,
  ) {
    super(rule);
  }
}

/** 讀 body：支援 Content-Encoding: gzip；計實際位元組數，不信任 Content-Length。 */
export async function readIngestBody(req: Request, maxCompressed = LIMITS.compressedBytes): Promise<{ value: unknown; bytes: number }> {
  let raw: Buffer;
  try {
    raw = await readBytes(req, maxCompressed);
  } catch (e) {
    if (e instanceof BodyTooLarge) throw new IngestRejected(413, 'too_large');
    throw e;
  }
  let text: string;
  const enc = (req.headers.get('content-encoding') ?? '').toLowerCase();
  if (enc === 'gzip') {
    try {
      text = zlib.gunzipSync(raw, { maxOutputLength: LIMITS.decompressedBytes }).toString('utf8');
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === 'ERR_BUFFER_TOO_LARGE' || (e instanceof RangeError)) throw new IngestRejected(413, 'decompressed_too_large');
      throw new IngestRejected(400, 'bad_gzip');
    }
  } else if (enc === '' || enc === 'identity') {
    text = raw.toString('utf8');
  } else {
    throw new IngestRejected(415, 'unsupported_encoding');
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new IngestRejected(400, 'bad_json');
  }
  walk(value);
  return { value, bytes: raw.length };
}

/** 結構上限檢查（在 zod 之前，避免病態 payload 吃掉 CPU）。 */
export function walk(root: unknown): void {
  let nodes = 0;
  const stack: Array<{ v: unknown; d: number }> = [{ v: root, d: 0 }];
  while (stack.length) {
    const { v, d } = stack.pop()!;
    if (++nodes > LIMITS.nodes) throw new IngestRejected(400, 'too_many_values');
    if (d > LIMITS.depth) throw new IngestRejected(400, 'too_deep');
    if (typeof v === 'string') {
      if (v.length > LIMITS.stringLength) throw new IngestRejected(400, 'string_too_long');
    } else if (typeof v === 'number') {
      if (!Number.isFinite(v) || Math.abs(v) > LIMITS.magnitude) throw new IngestRejected(400, 'number_out_of_range');
    } else if (Array.isArray(v)) {
      if (v.length > LIMITS.arrayLength) throw new IngestRejected(400, 'array_too_long');
      for (const x of v) stack.push({ v: x, d: d + 1 });
    } else if (v && typeof v === 'object') {
      const keys = Object.keys(v);
      if (keys.length > LIMITS.objectKeys) throw new IngestRejected(400, 'too_many_keys');
      for (const k of keys) {
        if (FORBIDDEN_KEYS.has(k)) throw new IngestRejected(400, 'forbidden_key');
        if (k.length > LIMITS.keyLength) throw new IngestRejected(400, 'key_too_long');
        stack.push({ v: (v as Record<string, unknown>)[k], d: d + 1 });
      }
    }
  }
}
