// AI 回答用的 Markdown 解析器（GFM 子集）：標題、段落、粗體／斜體／刪除線、行內程式碼、程式碼區塊、清單（可巢狀）、
// 引用、表格、分隔線、連結。只產生資料結構，由 components/ui/Markdown.tsx 轉成 React 元素（不經 innerHTML，沒有 XSS）。
// 串流中途（例如程式碼區塊或粗體還沒結束）也能正常顯示。桌面版 desktop/ui/markdown.js 是同一套規則的純 JS 版。

export type Inline =
  | { t: 'text'; v: string }
  | { t: 'code'; v: string }
  | { t: 'br' }
  | { t: 'strong' | 'em' | 'del'; c: Inline[] }
  | { t: 'link'; href: string; c: Inline[] };

export type Align = 'left' | 'center' | 'right' | null;

export type Block =
  | { t: 'h'; level: 1 | 2 | 3 | 4 | 5 | 6; c: Inline[] }
  | { t: 'p'; c: Inline[] }
  | { t: 'pre'; lang: string; v: string }
  | { t: 'hr' }
  | { t: 'quote'; c: Block[] }
  | { t: 'list'; ordered: boolean; start: number; items: Block[][] }
  | { t: 'table'; align: Align[]; head: Inline[][]; rows: Inline[][][] };

const FENCE = /^ {0,3}(`{3,}|~{3,})\s*([\w+#.-]*)/;
const HEADING = /^ {0,3}(#{1,6})\s+(.*?)(?:\s+#+)?\s*$/;
const HR = /^ {0,3}([-*_])(\s*\1){2,}\s*$/;
const QUOTE = /^ {0,3}>\s?/;
const ITEM = /^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$/;
const TABLE_SEP = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;

const indentOf = (s: string) => s.replace(/\t/g, '    ').match(/^ */)![0].length;
const isBlank = (s: string) => !s.trim();
const isTableStart = (lines: string[], i: number) => lines[i].includes('|') && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]) && lines[i + 1].includes('-');

function startsBlock(lines: string[], i: number): boolean {
  const l = lines[i];
  return FENCE.test(l) || HEADING.test(l) || HR.test(l) || QUOTE.test(l) || ITEM.test(l) || isTableStart(lines, i);
}

export function parseMarkdown(src: string): Block[] {
  return parseBlocks(src.replace(/\r\n?/g, '\n').split('\n'));
}

function parseBlocks(lines: string[]): Block[] {
  const out: Block[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (isBlank(line)) {
      i++;
      continue;
    }
    const fence = FENCE.exec(line);
    if (fence) {
      const close = new RegExp(`^ {0,3}${fence[1][0]}{${fence[1].length},}\\s*$`);
      const body: string[] = [];
      i++;
      while (i < lines.length && !close.test(lines[i])) body.push(lines[i++]);
      i++; // 結尾的 ```（串流中還沒出現也沒關係）
      out.push({ t: 'pre', lang: fence[2], v: body.join('\n') });
      continue;
    }
    const h = HEADING.exec(line);
    if (h) {
      out.push({ t: 'h', level: h[1].length as 1, c: parseInline(h[2]) });
      i++;
      continue;
    }
    if (HR.test(line)) {
      out.push({ t: 'hr' });
      i++;
      continue;
    }
    if (QUOTE.test(line)) {
      const inner: string[] = [];
      while (i < lines.length && !isBlank(lines[i]) && (QUOTE.test(lines[i]) || !startsBlock(lines, i))) inner.push(lines[i++].replace(QUOTE, ''));
      out.push({ t: 'quote', c: parseBlocks(inner) });
      continue;
    }
    if (isTableStart(lines, i)) {
      const head = splitRow(line);
      const align = splitRow(lines[i + 1]).map((c): Align => {
        const l = c.startsWith(':');
        const r = c.endsWith(':');
        return l && r ? 'center' : r ? 'right' : l ? 'left' : null;
      });
      i += 2;
      const rows: Inline[][][] = [];
      while (i < lines.length && !isBlank(lines[i]) && lines[i].includes('|')) {
        const cells = splitRow(lines[i++]);
        rows.push(head.map((_, k) => parseInline(cells[k] ?? '')));
      }
      out.push({ t: 'table', align: head.map((_, k) => align[k] ?? null), head: head.map((c) => parseInline(c)), rows });
      continue;
    }
    if (ITEM.test(line)) {
      i = parseList(lines, i, out);
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && !isBlank(lines[i]) && (para.length === 0 || !startsBlock(lines, i))) para.push(lines[i++].trim());
    out.push({ t: 'p', c: joinLines(para) });
  }
  return out;
}

function parseList(lines: string[], i: number, out: Block[]): number {
  const first = ITEM.exec(lines[i])!;
  const base = indentOf(first[1]);
  const ordered = /\d/.test(first[2]);
  const items: string[][] = [];
  while (i < lines.length) {
    const line = lines[i];
    const m = ITEM.exec(line);
    if (m && indentOf(m[1]) === base) {
      if (/\d/.test(m[2]) !== ordered) break;
      items.push([m[3]]);
      i++;
      continue;
    }
    if (isBlank(line)) {
      // 空行後接同一份清單的下一項或縮排內容才延續
      let j = i + 1;
      while (j < lines.length && isBlank(lines[j])) j++;
      const next = j < lines.length ? lines[j] : '';
      const nm = ITEM.exec(next);
      if ((nm && indentOf(nm[1]) === base && /\d/.test(nm[2]) === ordered) || (next && indentOf(next) > base)) {
        items[items.length - 1].push('');
        i++;
        continue;
      }
      break;
    }
    if (indentOf(line) > base) {
      items[items.length - 1].push(line.replace(/\t/g, '    ').slice(Math.min(indentOf(line), base + 2)));
      i++;
      continue;
    }
    // 沒有縮排的接續行（lazy continuation）只接在段落後面
    if (startsBlock(lines, i)) break;
    items[items.length - 1].push(line.trim());
    i++;
  }
  out.push({ t: 'list', ordered, start: ordered ? Number.parseInt(first[2], 10) : 1, items: items.map((it) => parseBlocks(it)) });
  return i;
}

function joinLines(lines: string[]): Inline[] {
  const out: Inline[] = [];
  lines.forEach((l, k) => {
    if (k) out.push({ t: 'br' });
    out.push(...parseInline(l));
  });
  return out;
}

/** 表格列：依 | 切，行內程式碼裡的 | 與 \| 不切。 */
function splitRow(line: string): string[] {
  let s = line.trim();
  if (s.startsWith('|')) s = s.slice(1);
  if (s.endsWith('|') && !s.endsWith('\\|')) s = s.slice(0, -1);
  const cells: string[] = [];
  let cur = '';
  let tick = 0;
  for (let k = 0; k < s.length; k++) {
    const ch = s[k];
    if (ch === '\\' && s[k + 1] === '|') {
      cur += tick ? '\\|' : '|';
      k++;
    } else if (ch === '`') {
      let n = 1;
      while (s[k + n] === '`') n++;
      tick = tick === 0 ? n : tick === n ? 0 : tick;
      cur += '`'.repeat(n);
      k += n - 1;
    } else if (ch === '|' && !tick) {
      cells.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  cells.push(cur.trim());
  return cells;
}

const URL_RE = /^https?:\/\/[^\s<>"'`()（）「」，。、；！？]+/;

/** 只允許 http(s)、mailto 與站內路徑（/ 開頭但不是 //）。 */
export function safeHref(href: string): string | null {
  const h = href.trim();
  if (/^https?:\/\//i.test(h) || /^mailto:/i.test(h)) return h;
  if (h.startsWith('/') && !h.startsWith('//')) return h;
  return null;
}

export function parseInline(src: string): Inline[] {
  const out: Inline[] = [];
  let text = '';
  const flush = () => {
    if (text) out.push({ t: 'text', v: text });
    text = '';
  };
  let k = 0;
  while (k < src.length) {
    const ch = src[k];
    const rest = src.slice(k);
    if (ch === '\\' && k + 1 < src.length && /[\\`*_{}[\]()#+\-.!|~<>]/.test(src[k + 1])) {
      text += src[k + 1];
      k += 2;
      continue;
    }
    if (ch === '`') {
      const run = /^`+/.exec(rest)![0];
      const end = src.indexOf(run, k + run.length);
      if (end > -1) {
        flush();
        const v = src.slice(k + run.length, end);
        out.push({ t: 'code', v: /^ .*[^ ].* $/.test(v) ? v.slice(1, -1) : v });
        k = end + run.length;
        continue;
      }
    }
    const pair = (mark: string, t: 'strong' | 'em' | 'del') => {
      if (!rest.startsWith(mark) || /\s/.test(src[k + mark.length] ?? ' ')) return false;
      let end = src.indexOf(mark, k + mark.length + 1);
      // 「*」斜體：跳過屬於「**」的位置
      while (mark === '*' && end > -1 && (src[end + 1] === '*' || src[end - 1] === '*')) end = src.indexOf(mark, end + 2);
      if (end < 0 || /\s/.test(src[end - 1])) return false;
      flush();
      out.push({ t, c: parseInline(src.slice(k + mark.length, end)) });
      k = end + mark.length;
      return true;
    };
    if (ch === '*' && (pair('**', 'strong') || pair('*', 'em'))) continue;
    if (ch === '_' && rest.startsWith('__') && pair('__', 'strong')) continue;
    if (ch === '~' && pair('~~', 'del')) continue;
    if (ch === '[') {
      const m = /^\[([^\]\n]+)\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/.exec(rest);
      const href = m ? safeHref(m[2]) : null;
      if (m && href) {
        flush();
        out.push({ t: 'link', href, c: parseInline(m[1]) });
        k += m[0].length;
        continue;
      }
    }
    if ((ch === 'h' || ch === 'H') && (k === 0 || !/[\w/]/.test(src[k - 1]))) {
      const m = URL_RE.exec(rest);
      if (m) {
        const url = m[0].replace(/[.,;:!?]+$/, '');
        flush();
        out.push({ t: 'link', href: url, c: [{ t: 'text', v: url }] });
        k += url.length;
        continue;
      }
    }
    text += ch;
    k++;
  }
  flush();
  return out;
}
