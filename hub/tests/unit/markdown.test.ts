import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Markdown } from '@/components/ui/Markdown';
import { parseInline, parseMarkdown, safeHref } from '@/lib/markdown';

const AI_ANSWER = `## 結論

**目前沒有需要封鎖的連線。** 全部可疑判定都只是**行為判斷**（beaconing），屬**誤報**。

| 行程 | 目的地 | 判定原因 |
|---|:---:|---:|
| Code.exe（\`...\\Microsoft VS Code\\Code.exe\`，PID 54876） | 150.171.110.68:443 | beaconing：週期 307 秒 |
| \`a|b\` | x \\| y | |

- 同一個 IP 同時也有 chrome.exe 在連。
- 研判：VS Code 會定期連回 Microsoft 端點
  - 巢狀項目 \`lookup_indicator\`
1. 第一步
2. 第二步`;

describe('parseMarkdown', () => {
  it('parses headings, bold, tables (with code and escaped pipes) and lists from an AI answer', () => {
    const b = parseMarkdown(AI_ANSWER);
    expect(b.map((x) => x.t)).toEqual(['h', 'p', 'table', 'list', 'list']);
    expect(b[0]).toEqual({ t: 'h', level: 2, c: [{ t: 'text', v: '結論' }] });
    const p = b[1] as Extract<(typeof b)[number], { t: 'p' }>;
    expect(p.c[0]).toEqual({ t: 'strong', c: [{ t: 'text', v: '目前沒有需要封鎖的連線。' }] });
    expect(p.c.filter((n) => n.t === 'strong')).toHaveLength(3);

    const table = b[2] as Extract<(typeof b)[number], { t: 'table' }>;
    expect(table.align).toEqual([null, 'center', 'right']);
    expect(table.head).toHaveLength(3);
    expect(table.rows).toHaveLength(2);
    expect(table.rows[0][0]).toContainEqual({ t: 'code', v: '...\\Microsoft VS Code\\Code.exe' });
    expect(table.rows[1][0]).toEqual([{ t: 'code', v: 'a|b' }]);
    expect(table.rows[1][1]).toEqual([{ t: 'text', v: 'x | y' }]);
    expect(table.rows[1][2]).toEqual([]);

    const ul = b[3] as Extract<(typeof b)[number], { t: 'list' }>;
    expect(ul.ordered).toBe(false);
    expect(ul.items).toHaveLength(2);
    expect(ul.items[1].map((x) => x.t)).toEqual(['p', 'list']);
    const nested = ul.items[1][1] as Extract<(typeof b)[number], { t: 'list' }>;
    expect(nested.items[0][0]).toEqual({ t: 'p', c: [{ t: 'text', v: '巢狀項目 ' }, { t: 'code', v: 'lookup_indicator' }] });

    const ol = b[4] as Extract<(typeof b)[number], { t: 'list' }>;
    expect(ol).toMatchObject({ ordered: true, start: 1 });
    expect(ol.items).toHaveLength(2);
  });

  it('keeps line breaks inside a paragraph and handles code fences, quotes and rules', () => {
    const b = parseMarkdown('第一行\n第二行\n\n```bash\nai-security-monitor scan\n```\n\n> 引用\n\n---');
    expect(b[0]).toEqual({ t: 'p', c: [{ t: 'text', v: '第一行' }, { t: 'br' }, { t: 'text', v: '第二行' }] });
    expect(b[1]).toEqual({ t: 'pre', lang: 'bash', v: 'ai-security-monitor scan' });
    expect(b[2]).toEqual({ t: 'quote', c: [{ t: 'p', c: [{ t: 'text', v: '引用' }] }] });
    expect(b[3]).toEqual({ t: 'hr' });
    expect(parseMarkdown('### C# 與 F# ##')).toEqual([{ t: 'h', level: 3, c: [{ t: 'text', v: 'C# 與 F#' }] }]);
  });

  it('renders partial (still streaming) text without losing content', () => {
    expect(parseMarkdown('```js\nconst a = 1')).toEqual([{ t: 'pre', lang: 'js', v: 'const a = 1' }]);
    expect(parseInline('**還沒結束')).toEqual([{ t: 'text', v: '**還沒結束' }]);
    expect(parseMarkdown('| a | b |\n|---')).toHaveLength(1);
  });
});

describe('parseInline', () => {
  it('does not treat snake_case or lone asterisks as emphasis', () => {
    expect(parseInline('lookup_indicator 與 get_metrics')).toEqual([{ t: 'text', v: 'lookup_indicator 與 get_metrics' }]);
    expect(parseInline('5 * 3 * 2')).toEqual([{ t: 'text', v: '5 * 3 * 2' }]);
    expect(parseInline('*斜體* 與 ~~刪除~~')).toEqual([
      { t: 'em', c: [{ t: 'text', v: '斜體' }] },
      { t: 'text', v: ' 與 ' },
      { t: 'del', c: [{ t: 'text', v: '刪除' }] },
    ]);
  });

  it('only links safe URLs and trims trailing punctuation from bare URLs', () => {
    expect(parseInline('[IP 分析](/ip/45.155.205.233)')).toEqual([{ t: 'link', href: '/ip/45.155.205.233', c: [{ t: 'text', v: 'IP 分析' }] }]);
    expect(parseInline('[x](javascript:alert(1))')[0]).toMatchObject({ t: 'text' });
    expect(parseInline('見 https://example.com/a。')).toEqual([
      { t: 'text', v: '見 ' },
      { t: 'link', href: 'https://example.com/a', c: [{ t: 'text', v: 'https://example.com/a' }] },
      { t: 'text', v: '。' },
    ]);
    expect(safeHref('//evil.example')).toBeNull();
    expect(safeHref('data:text/html,x')).toBeNull();
  });
});

describe('Markdown component', () => {
  it('renders real HTML elements and escapes raw HTML in the text', () => {
    const html = renderToStaticMarkup(createElement(Markdown, { text: `${AI_ANSWER}\n\n<script>alert(1)</script> [x](javascript:alert(1))` }));
    for (const tag of ['<h3', '<strong', '<table', '<th', '<td', '<code', '<ul', '<ol', '<li']) expect(html).toContain(tag);
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).not.toContain('href="javascript:');
    expect(html).not.toContain('|---|');
  });
});
