// 可點的 IP：開 IP 分析頁（情資命中、哪些主機連過、歷史、請 AI 分析）。
import Link from 'next/link';
import type { ReactNode } from 'react';

/** 粗略判斷是 IPv4／IPv6（client 元件也能用，不依賴 node:net）。 */
export function looksLikeIp(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) ||(/^[0-9a-f:.]+$/i.test(s) && s.includes(':'));
}

export function ipHref(ip: string): string {
  return `/ip/${encodeURIComponent(ip)}`;
}

export function IpLink({ ip, children, className }: { ip: string | null | undefined; children: ReactNode; className?: string }) {
  if (!ip || !looksLikeIp(ip)) return <span className={className}>{children}</span>;
  return (
    <Link href={ipHref(ip)} className={`text-teal-700 hover:underline dark:text-teal-300 ${className ?? ''}`} title={ip}>
      {children}
    </Link>
  );
}
