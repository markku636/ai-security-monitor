// 動作的顯示文字（server 與 client 元件共用，所以不能放在 'use client' 檔）。
import type { TFn } from '@/lib/i18n/core';

export function describeAction(t: TFn, kind: string, p: Record<string, unknown>): string {
  const dir = ({ in: t('連入'), out: t('連出'), both: t('雙向') } as Record<string, string>)[String(p.direction ?? 'both')] ?? '';
  if (kind === 'block_ip') return t('封鎖 {ip}（{dir}）', { ip: String(p.ip), dir });
  if (kind === 'unblock_ip') return t('解除封鎖 {ip}', { ip: String(p.ip) });
  if (kind === 'close_port') return t('關閉連入 port {proto}/{port}', { proto: String(p.proto), port: String(p.port) });
  return kind;
}

export function actionStatusText(t: TFn, s: string): string {
  return (
    {
      pending: t('待核准'),
      approved: t('已核准'),
      dispatched: t('已派送'),
      succeeded: t('已完成'),
      failed: t('執行失敗'),
      rejected: t('已拒絕'),
      cancelled: t('已取消'),
      expired: t('已過期'),
    } as Record<string, string>
  )[s] ?? s;
}
