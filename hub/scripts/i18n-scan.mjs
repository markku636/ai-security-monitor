// 檢查 app/、components/、lib/ 裡所有 t('含中文的字面值') 都在 messages/en.ts 有英文。缺就 exit 1（CI 閘門）。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CJK = /[　-〿㐀-鿿＀-￯]/;
const CALL = /\bt\(\s*(['"])((?:\\.|(?!\1).)*)\1/g;

function walk(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(e.name) && !e.name.endsWith('.test.ts')) out.push(p);
  }
  return out;
}

const files = ['app', 'components', 'lib'].flatMap((d) => (fs.existsSync(path.join(root, d)) ? walk(path.join(root, d), []) : []));
const enSrc = fs.readFileSync(path.join(root, 'messages', 'en.ts'), 'utf8');
const keys = new Set([...enSrc.matchAll(/^\s*'((?:\\.|[^'])+)':/gm)].map((m) => m[1].replace(/\\'/g, "'")));

const missing = new Map();
for (const f of files) {
  const src = fs.readFileSync(f, 'utf8');
  for (const m of src.matchAll(CALL)) {
    const key = m[2].replace(/\\(['"])/g, '$1');
    if (CJK.test(key) && !keys.has(key)) {
      if (!missing.has(key)) missing.set(key, path.relative(root, f));
    }
  }
}

if (missing.size) {
  console.error(`i18n: ${missing.size} string(s) missing from messages/en.ts:`);
  for (const [k, f] of missing) console.error(`  ${f}: ${k}`);
  process.exit(1);
}
console.log(`i18n: ok (${keys.size} entries, ${files.length} files scanned)`);
