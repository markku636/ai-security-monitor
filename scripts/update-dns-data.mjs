#!/usr/bin/env node
// 更新內嵌在 agent 的 DNS 參考資料（feeds/dns/）：
//   public_suffix_list.dat — Mozilla Public Suffix List（MPL-2.0），算「可註冊網域」（eTLD+1）用。
//   toplist.txt            — Majestic Million 前 N 名（CC BY 3.0，需標註），只用來壓低 DGA／新網域這類推測型誤報。
// 用法：node scripts/update-dns-data.mjs [--top 10000]
// 發版前跑一次即可；檔案進 repo，執行期不下載。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, 'feeds', 'dns');
const topIdx = process.argv.indexOf('--top');
const TOP = topIdx > 0 ? Number(process.argv[topIdx + 1]) : 10000;

const PSL_URL = 'https://publicsuffix.org/list/public_suffix_list.dat';
const MAJESTIC_URL = 'https://downloads.majestic.com/majestic_million.csv';

async function get(url, init) {
  const r = await fetch(url, { ...init, headers: { 'user-agent': 'ai-security-monitor/update-dns-data', ...(init?.headers ?? {}) } });
  if (!r.ok && r.status !== 206) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
}

async function psl() {
  const text = await get(PSL_URL);
  if (!text.includes('===BEGIN ICANN DOMAINS===') || !text.includes('===BEGIN PRIVATE DOMAINS===')) {
    throw new Error('public suffix list looks wrong');
  }
  fs.writeFileSync(path.join(outDir, 'public_suffix_list.dat'), text.replace(/\r\n/g, '\n'));
  return text.split('\n').filter((l) => l && !l.startsWith('//')).length;
}

async function toplist() {
  // CSV 依排名排序：只抓前段（每行約 100 bytes），不用下載整份 80 MB。
  let bytes = TOP * 140 + 4096;
  for (;;) {
    const text = await get(MAJESTIC_URL, { headers: { range: `bytes=0-${bytes}` } });
    const lines = text.split('\n');
    lines.pop(); // 最後一行可能被截斷
    const header = lines.shift()?.split(',') ?? [];
    const col = header.indexOf('Domain');
    if (col < 0) throw new Error('majestic csv header changed');
    const domains = [];
    const seen = new Set();
    for (const l of lines) {
      const d = l.split(',')[col]?.trim().toLowerCase();
      if (!d || seen.has(d) || !/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(d)) continue;
      seen.add(d);
      domains.push(d);
      if (domains.length >= TOP) break;
    }
    if (domains.length >= TOP) {
      const head = [
        `# Majestic Million top ${TOP} (${new Date().toISOString().slice(0, 10)})`,
        '# Source: https://majestic.com/reports/majestic-million',
        '# License: CC BY 3.0 (https://creativecommons.org/licenses/by/3.0/), attribution: Majestic-12 Ltd',
        '# Used only to dampen heuristic (DGA / newly-seen) false positives; never as a safety guarantee.',
      ];
      fs.writeFileSync(path.join(outDir, 'toplist.txt'), `${head.join('\n')}\n${domains.join('\n')}\n`);
      return domains.length;
    }
    bytes *= 2;
  }
}

fs.mkdirSync(outDir, { recursive: true });
const [a, b] = await Promise.all([psl(), toplist()]);
console.log(`public_suffix_list.dat: ${a} rules; toplist.txt: ${b} domains`);
