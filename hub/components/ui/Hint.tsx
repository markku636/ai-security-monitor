// 專有名詞旁的小「?」：滑鼠移上去（或鍵盤聚焦）顯示一句白話說明。server／client 都能用（沒有 hook）。
export function Hint({ text, label = '?' }: { text: string; label?: string }) {
  return (
    <span
      tabIndex={0}
      role="note"
      title={text}
      aria-label={text}
      className="ml-1 inline-flex h-4 min-w-4 cursor-help items-center justify-center rounded-full border border-slate-300 px-1 align-middle text-[10px] font-medium leading-none text-slate-500 hover:border-teal-500 hover:text-teal-700 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-slate-600 dark:text-slate-400 dark:hover:text-teal-400"
    >
      {label}
    </span>
  );
}

/** 有虛線底線的術語，滑鼠移上去看解釋。 */
export function Term({ children, hint }: { children: string; hint: string }) {
  return (
    <abbr title={hint} className="cursor-help underline decoration-dotted decoration-slate-400 underline-offset-2 [text-decoration-line:underline]">
      {children}
    </abbr>
  );
}
