// 檢查 server 端檔案有沒有從 'use client' 模組 import「非元件」的值（小寫開頭的函式／常數）。
// 這種呼叫在執行時才會爆（Attempted to call X() from the server…），typecheck 抓不到。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function walk(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(e.name)) out.push(p);
  }
  return out;
}

const files = ['app', 'components', 'lib'].flatMap((d) => walk(path.join(root, d), []));
const isClient = (src) => /^\s*(?:\/\/[^\n]*\n|\s)*['"]use client['"]/.test(src);
const src = new Map(files.map((f) => [f, fs.readFileSync(f, 'utf8')]));
const clientFiles = new Set(files.filter((f) => isClient(src.get(f))));

function resolve(from, spec) {
  let base;
  if (spec.startsWith('@/')) base = path.join(root, spec.slice(2));
  else if (spec.startsWith('.')) base = path.resolve(path.dirname(from), spec);
  else return null;
  for (const ext of ['', '.ts', '.tsx', '/index.ts', '/index.tsx']) {
    if (src.has(base + ext)) return base + ext;
  }
  return null;
}

const IMPORT = /import\s+(type\s+)?\{([^}]*)\}\s+from\s+['"]([^'"]+)['"]/g;
const problems = [];
for (const f of files) {
  if (clientFiles.has(f)) continue;
  for (const m of src.get(f).matchAll(IMPORT)) {
    if (m[1]) continue;
    const target = resolve(f, m[3]);
    if (!target || !clientFiles.has(target)) continue;
    for (const raw of m[2].split(',')) {
      const name = raw.trim();
      if (!name || name.startsWith('type ')) continue;
      const local = name.split(/\s+as\s+/)[0].trim();
      if (/^[a-z]/.test(local)) problems.push(`${path.relative(root, f)}: '${local}' comes from client module ${path.relative(root, target)}`);
    }
  }
}

if (problems.length) {
  console.error('server files import non-component values from "use client" modules:');
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`client-imports: ok (${clientFiles.size} client modules)`);
