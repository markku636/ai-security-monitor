// 依掃描器分派解析；新增掃描器時在這裡加一行，並在 scanners.ts 的登錄表加上它。
import type { WebscanScanner } from '../scanners';
import { parseHttpx } from './httpx';
import { parseNuclei } from './nuclei';
import { parseTestssl } from './testssl';
import { parseTlsx } from './tlsx';
import type { ParseContext, ParseOutput } from './types';

const PARSERS: Record<WebscanScanner, (text: string, ctx: ParseContext) => ParseOutput> = {
  httpx: parseHttpx,
  tlsx: parseTlsx,
  nuclei: parseNuclei,
  testssl: parseTestssl,
};

export function parseArtifact(scanner: WebscanScanner, text: string, ctx: ParseContext): ParseOutput {
  try {
    return PARSERS[scanner](text, ctx);
  } catch (e) {
    return { findings: [], warnings: [`${scanner}:parse_error:${e instanceof Error ? e.message.slice(0, 120) : 'unknown'}`] };
  }
}

export type { NormalizedFinding, ParseContext, ParseOutput, Severity } from './types';
