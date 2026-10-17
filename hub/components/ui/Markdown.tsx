// AI 回答的 Markdown 顯示：lib/markdown.ts 解析後轉成 React 元素（不用 innerHTML）。server／client 都能用（沒有 hook）。
import type { ReactNode } from 'react';
import { type Block, type Inline, parseMarkdown } from '@/lib/markdown';

const H_CLASS = ['', 'text-lg font-semibold', 'text-base font-semibold', 'text-sm font-semibold', 'text-sm font-semibold', 'text-sm font-medium', 'text-sm font-medium'];

function inlines(nodes: Inline[]): ReactNode[] {
  return nodes.map((n, i) => {
    switch (n.t) {
      case 'text':
        return n.v;
      case 'br':
        return <br key={i} />;
      case 'code':
        return (
          <code key={i} className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[0.85em] dark:bg-slate-800">
            {n.v}
          </code>
        );
      case 'strong':
        return (
          <strong key={i} className="font-semibold">
            {inlines(n.c)}
          </strong>
        );
      case 'em':
        return <em key={i}>{inlines(n.c)}</em>;
      case 'del':
        return <del key={i}>{inlines(n.c)}</del>;
      case 'link': {
        const external = /^https?:/i.test(n.href);
        return (
          <a
            key={i}
            href={n.href}
            className="text-teal-700 underline underline-offset-2 hover:text-teal-900 dark:text-teal-400 dark:hover:text-teal-300"
            {...(external ? { target: '_blank', rel: 'noopener noreferrer nofollow' } : {})}
          >
            {inlines(n.c)}
          </a>
        );
      }
    }
  });
}

function blocks(nodes: Block[], tight = false): ReactNode[] {
  return nodes.map((b, i) => {
    switch (b.t) {
      case 'h': {
        const Tag = `h${Math.min(b.level + 1, 6)}` as 'h2';
        return (
          <Tag key={i} className={`${H_CLASS[b.level]} mt-4 first:mt-0`}>
            {inlines(b.c)}
          </Tag>
        );
      }
      case 'p':
        return tight ? <div key={i}>{inlines(b.c)}</div> : <p key={i}>{inlines(b.c)}</p>;
      case 'pre':
        return (
          <pre key={i} className="overflow-x-auto rounded-md bg-slate-100 p-3 font-mono text-xs leading-relaxed dark:bg-slate-800">
            <code>{b.v}</code>
          </pre>
        );
      case 'hr':
        return <hr key={i} className="border-slate-200 dark:border-slate-700" />;
      case 'quote':
        return (
          <blockquote key={i} className="space-y-2 border-l-4 border-slate-300 pl-3 text-slate-600 dark:border-slate-600 dark:text-slate-300">
            {blocks(b.c)}
          </blockquote>
        );
      case 'list': {
        const items = b.items.map((it, k) => (
          <li key={k} className="space-y-1">
            {blocks(it, true)}
          </li>
        ));
        return b.ordered ? (
          <ol key={i} start={b.start} className="list-decimal space-y-1 pl-6">
            {items}
          </ol>
        ) : (
          <ul key={i} className="list-disc space-y-1 pl-6">
            {items}
          </ul>
        );
      }
      case 'table':
        return (
          <div key={i} className="overflow-x-auto">
            <table className="min-w-full border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-slate-300 dark:border-slate-600">
                  {b.head.map((c, k) => (
                    <th key={k} className="px-2 py-1.5 font-semibold" style={b.align[k] ? { textAlign: b.align[k]! } : undefined}>
                      {inlines(c)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {b.rows.map((r, k) => (
                  <tr key={k} className="border-b border-slate-100 align-top dark:border-slate-800">
                    {r.map((c, j) => (
                      <td key={j} className="px-2 py-1.5" style={b.align[j] ? { textAlign: b.align[j]! } : undefined}>
                        {inlines(c)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
    }
  });
}

export function Markdown({ text, className = '' }: { text: string; className?: string }) {
  return <div className={`space-y-3 text-sm leading-relaxed break-words ${className}`}>{blocks(parseMarkdown(text))}</div>;
}
