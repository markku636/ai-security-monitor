// 主機清單／主機頁的「有新版 0.x.y」：滑鼠移上去說明這台會怎麼更新（自動、桌面版、或要手動）。
import { Badge } from '@/components/ui/Badge';
import type { TFn } from '@/lib/i18n/core';
import type { AgentUpdateLike } from '@/lib/update';

export function updateHowText(t: TFn, info: AgentUpdateLike | null | undefined): string {
  if (info?.owner === 'desktop') return t('這台用的是桌面版：在那台電腦的桌面版按「設定 → 立即更新」（設成自動更新就會自己更新）。');
  if (info?.mode === 'auto') return t('這台設定為自動更新：背景服務會在一天內自己下載、驗證並更新。');
  return t('到那台電腦執行 ai-security-monitor self-update --yes，或設定 ai-security-monitor config set update.mode auto 讓它自動更新。');
}

export function UpdateBadge({ t, latest, info }: { t: TFn; latest: string | null; info?: AgentUpdateLike | null }) {
  if (!latest) return null;
  return (
    <span title={updateHowText(t, info)} className="cursor-help">
      <Badge tone="info">{t('有新版 {v}', { v: latest })}</Badge>
    </span>
  );
}

/** update.mode 的白話說明。 */
export function updateModeText(t: TFn, mode: string | null | undefined): string {
  if (mode === 'off') return t('關閉');
  if (mode === 'auto') return t('自動更新');
  if (mode === 'notify') return t('有新版時通知');
  return '—';
}
