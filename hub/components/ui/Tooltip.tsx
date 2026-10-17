'use client';

// 即時提示泡泡：滑鼠移入或鍵盤聚焦就出現（不用等原生 title 的延遲），觸控點一下切換，Esc 關閉。
// 用 position: fixed 依觸發元素位置計算，所以不會被表格的 overflow 裁掉；捲動／縮放時跟著重算。
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';

const GAP = 6;
const EDGE = 8;

export function Tooltip({
  text,
  children,
  className = '',
  as = 'span',
}: {
  text: string;
  children: ReactNode;
  className?: string;
  /** 觸發元素的標籤（包住區塊內容時用 div）。 */
  as?: 'span' | 'div';
}) {
  const id = useId();
  const trigger = useRef<HTMLElement | null>(null);
  const tip = useRef<HTMLSpanElement | null>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  const place = useCallback(() => {
    const el = trigger.current;
    const bubble = tip.current;
    if (!el || !bubble) return;
    const r = el.getBoundingClientRect();
    const b = bubble.getBoundingClientRect();
    const vw = window.innerWidth;
    const left = Math.min(Math.max(EDGE, r.left + r.width / 2 - b.width / 2), Math.max(EDGE, vw - b.width - EDGE));
    const above = r.top - b.height - GAP;
    const top = above >= EDGE ? above : r.bottom + GAP;
    setPos({ top, left });
  }, []);

  useLayoutEffect(() => {
    if (open) place();
    else setPos(null);
  }, [open, place, text]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    const onPointer = (e: PointerEvent) => {
      if (trigger.current && !trigger.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    window.addEventListener('keydown', onKey);
    window.addEventListener('pointerdown', onPointer);
    return () => {
      window.removeEventListener('scroll', place, true);
      window.removeEventListener('resize', place);
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('pointerdown', onPointer);
    };
  }, [open, place]);

  const Tag = as;
  return (
    <Tag
      ref={(el: HTMLElement | null) => {
        trigger.current = el;
      }}
      tabIndex={0}
      aria-describedby={id}
      className={className}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onClick={(e) => {
        // 觸控裝置沒有 hover：點一下切換
        if ((e.nativeEvent as PointerEvent).pointerType === 'touch') setOpen((v) => !v);
      }}
    >
      {children}
      <span
        ref={tip}
        id={id}
        role="tooltip"
        hidden={!open}
        style={{ position: 'fixed', top: pos?.top ?? -9999, left: pos?.left ?? -9999, maxWidth: 'min(20rem, calc(100vw - 16px))' }}
        className="pointer-events-none z-50 block w-max whitespace-normal rounded-md bg-slate-900 px-2.5 py-1.5 text-left text-xs font-normal normal-case leading-relaxed tracking-normal text-white shadow-lg dark:bg-slate-100 dark:text-slate-900"
      >
        {text}
      </span>
    </Tag>
  );
}
