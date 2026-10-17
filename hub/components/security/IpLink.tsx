// 可點的 IP：開 IP 分析頁（情資命中、哪些主機連過、歷史、請 AI 分析）。
import Link from 'next/link';
import type { ReactNode } from 'react';
import type { TFn } from '@/lib/i18n/core';
import type { IpRisk } from '@/lib/ipintel/types';
import { IpRiskIcon } from './IpRisk';

/** 粗略判斷是 IPv4／IPv6（client 元件也能用，不依賴 node:net）。 */
export function looksLikeIp(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) ||(/^[0-9a-f:.]+$/i.test(s) && s.includes(':'));
}

export function ipHref(ip: string): string {
  return `/ip/${encodeURIComponent(ip)}`;
}

/**
 * `risk`＋`t` 有給時，IP 前面加外部風險圖示（低／中／高／極高／尚未查詢；內網不顯示）。
 * 風險請整頁一次查（cachedRisks），不要每列各查一次。
 */
export function IpLink({
  ip,
  children,
  className,
  risk,
  t,
}: {
  ip: string | null | undefined;
  children: ReactNode;
  className?: string;
  risk?: IpRisk | null;
  t?: TFn;
}) {
  if (!ip || !looksLikeIp(ip)) return <span className={className}>{children}</span>;
  const link = (
    <Link href={ipHref(ip)} className={`text-teal-700 hover:underline dark:text-teal-300 ${className ?? ''}`} title={ip}>
      {children}
    </Link>
  );
  if (!t || !risk || risk.kind === 'private') return link;
  return (
    <span className="inline-flex items-center gap-1 align-middle">
      <IpRiskIcon t={t} risk={risk} />
      {link}
    </span>
  );
}
