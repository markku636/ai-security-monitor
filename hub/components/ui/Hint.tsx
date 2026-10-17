// 專有名詞旁的小「?」與虛線底線術語：滑鼠移上去（或鍵盤聚焦、觸控點一下）立即顯示一句白話說明。
// 本身沒有 hook，server／client 元件都能用；提示泡泡由 Tooltip（client）負責。
import { Tooltip } from './Tooltip';

export function Hint({ text, label = '?' }: { text: string; label?: string }) {
  return (
    <Tooltip
      text={text}
      className="ml-1 inline-flex h-4 min-w-4 cursor-help items-center justify-center rounded-full border border-slate-300 px-1 align-middle text-[10px] font-medium leading-none text-slate-500 hover:border-teal-500 hover:text-teal-700 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-slate-600 dark:text-slate-400 dark:hover:text-teal-400"
    >
      {label}
    </Tooltip>
  );
}

/** 有虛線底線的術語，滑鼠移上去看解釋。 */
export function Term({ children, hint }: { children: string; hint: string }) {
  return (
    <Tooltip
      text={hint}
      className="cursor-help underline decoration-slate-400 decoration-dotted underline-offset-2 focus:outline-none focus-visible:ring-1 focus-visible:ring-teal-500"
    >
      {children}
    </Tooltip>
  );
}
