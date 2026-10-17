// AI 回答的 Markdown 顯示（GFM 子集）：標題、段落、粗體／斜體／刪除線、行內程式碼、程式碼區塊、清單（可巢狀）、引用、表格、分隔線、連結。
// 規則與 hub/lib/markdown.ts 相同；這裡直接用 createElement／textContent 組 DOM（不用 innerHTML，沒有 XSS）。
// 串流中途（程式碼區塊或粗體還沒結束）也能正常顯示。用法：renderMarkdown(element, text)。
(function () {
  const FENCE = /^ {0,3}(`{3,}|~{3,})\s*([\w+#.-]*)/;
  const HEADING = /^ {0,3}(#{1,6})\s+(.*?)(?:\s+#+)?\s*$/;
  const HR = /^ {0,3}([-*_])(\s*\1){2,}\s*$/;
  const QUOTE = /^ {0,3}>\s?/;
  const ITEM = /^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$/;
  const TABLE_SEP = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;
  const URL_RE = /^https?:\/\/[^\s<>"'`()（）「」，。、；！？]+/;

  const indentOf = (s) => s.replace(/\t/g, '    ').match(/^ */)[0].length;
  const isBlank = (s) => !s.trim();
  const isTableStart = (lines, i) => lines[i].includes('|') && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]) && lines[i + 1].includes('-');
  const startsBlock = (lines, i) => {
    const l = lines[i];
    return FENCE.test(l) || HEADING.test(l) || HR.test(l) || QUOTE.test(l) || ITEM.test(l) || isTableStart(lines, i);
  };

  function parseBlocks(lines) {
    const out = [];
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
        const body = [];
        i++;
        while (i < lines.length && !close.test(lines[i])) body.push(lines[i++]);
        i++;
        out.push({ t: 'pre', v: body.join('\n') });
        continue;
      }
      const h = HEADING.exec(line);
      if (h) {
        out.push({ t: 'h', level: h[1].length, c: parseInline(h[2]) });
        i++;
        continue;
      }
      if (HR.test(line)) {
        out.push({ t: 'hr' });
        i++;
        continue;
      }
      if (QUOTE.test(line)) {
        const inner = [];
        while (i < lines.length && !isBlank(lines[i]) && (QUOTE.test(lines[i]) || !startsBlock(lines, i))) inner.push(lines[i++].replace(QUOTE, ''));
        out.push({ t: 'quote', c: parseBlocks(inner) });
        continue;
      }
      if (isTableStart(lines, i)) {
        const head = splitRow(line);
        const align = splitRow(lines[i + 1]).map((c) => {
          const l = c.startsWith(':');
          const r = c.endsWith(':');
          return l && r ? 'center' : r ? 'right' : l ? 'left' : null;
        });
        i += 2;
        const rows = [];
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
      const para = [];
      while (i < lines.length && !isBlank(lines[i]) && (para.length === 0 || !startsBlock(lines, i))) para.push(lines[i++].trim());
      const c = [];
      para.forEach((l, k) => {
        if (k) c.push({ t: 'br' });
        c.push(...parseInline(l));
      });
      out.push({ t: 'p', c });
    }
    return out;
  }

  function parseList(lines, i, out) {
    const first = ITEM.exec(lines[i]);
    const base = indentOf(first[1]);
    const ordered = /\d/.test(first[2]);
    const items = [];
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
      if (startsBlock(lines, i)) break;
      items[items.length - 1].push(line.trim());
      i++;
    }
    out.push({ t: 'list', ordered, start: ordered ? Number.parseInt(first[2], 10) : 1, items: items.map((it) => parseBlocks(it)) });
    return i;
  }

  function splitRow(line) {
    let s = line.trim();
    if (s.startsWith('|')) s = s.slice(1);
    if (s.endsWith('|') && !s.endsWith('\\|')) s = s.slice(0, -1);
    const cells = [];
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

  function safeHref(href) {
    const h = href.trim();
    return /^https?:\/\//i.test(h) ? h : null; // 桌面版只開 http(s)，交給 open_url 用預設瀏覽器開
  }

  function parseInline(src) {
    const out = [];
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
        const run = /^`+/.exec(rest)[0];
        const end = src.indexOf(run, k + run.length);
        if (end > -1) {
          flush();
          const v = src.slice(k + run.length, end);
          out.push({ t: 'code', v: /^ .*[^ ].* $/.test(v) ? v.slice(1, -1) : v });
          k = end + run.length;
          continue;
        }
      }
      const pair = (mark, t) => {
        if (!rest.startsWith(mark) || /\s/.test(src[k + mark.length] ?? ' ')) return false;
        let end = src.indexOf(mark, k + mark.length + 1);
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

  // ---------------- DOM ----------------
  const el = (tag, cls) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    return e;
  };

  function appendInline(parent, nodes) {
    for (const n of nodes) {
      if (n.t === 'text') parent.appendChild(document.createTextNode(n.v));
      else if (n.t === 'br') parent.appendChild(el('br'));
      else if (n.t === 'code') {
        const c = el('code');
        c.textContent = n.v;
        parent.appendChild(c);
      } else if (n.t === 'link') {
        const a = el('a');
        a.href = n.href;
        a.dataset.url = n.href; // app.js 的點擊處理用預設瀏覽器開
        appendInline(a, n.c);
        parent.appendChild(a);
      } else {
        const e = el(n.t);
        appendInline(e, n.c);
        parent.appendChild(e);
      }
    }
  }

  function appendBlocks(parent, blocks, tight) {
    for (const b of blocks) {
      if (b.t === 'h') {
        const h = el(`h${Math.min(b.level + 1, 6)}`);
        appendInline(h, b.c);
        parent.appendChild(h);
      } else if (b.t === 'p') {
        const p = el(tight ? 'div' : 'p');
        appendInline(p, b.c);
        parent.appendChild(p);
      } else if (b.t === 'pre') {
        const pre = el('pre');
        const code = el('code');
        code.textContent = b.v;
        pre.appendChild(code);
        parent.appendChild(pre);
      } else if (b.t === 'hr') parent.appendChild(el('hr'));
      else if (b.t === 'quote') {
        const q = el('blockquote');
        appendBlocks(q, b.c, false);
        parent.appendChild(q);
      } else if (b.t === 'list') {
        const list = el(b.ordered ? 'ol' : 'ul');
        if (b.ordered && b.start !== 1) list.start = b.start;
        for (const it of b.items) {
          const li = el('li');
          appendBlocks(li, it, true);
          list.appendChild(li);
        }
        parent.appendChild(list);
      } else if (b.t === 'table') {
        const wrap = el('div', 'md-table');
        const table = el('table');
        const tr = el('tr');
        b.head.forEach((c, k) => {
          const th = el('th');
          if (b.align[k]) th.style.textAlign = b.align[k];
          appendInline(th, c);
          tr.appendChild(th);
        });
        table.appendChild(el('thead')).appendChild(tr);
        const tbody = table.appendChild(el('tbody'));
        for (const r of b.rows) {
          const row = el('tr');
          r.forEach((c, k) => {
            const td = el('td');
            if (b.align[k]) td.style.textAlign = b.align[k];
            appendInline(td, c);
            row.appendChild(td);
          });
          tbody.appendChild(row);
        }
        wrap.appendChild(table);
        parent.appendChild(wrap);
      }
    }
  }

  window.renderMarkdown = function renderMarkdown(target, text) {
    target.replaceChildren();
    target.classList.add('md');
    appendBlocks(target, parseBlocks(String(text).replace(/\r\n?/g, '\n').split('\n')), false);
  };
})();
