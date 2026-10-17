// 問題的 MITRE ATT&CK 技術與法規控制項標籤（server／client 都能用：不用 hook，語言從 t 取）。滑過看白話說明。
import Link from 'next/link';
import { Tooltip } from '@/components/ui/Tooltip';
import { CONTROLS, FRAMEWORKS, TACTICS, TECHNIQUES, frameworkOf } from '@/lib/attack/catalog';
import { langOf, type TFn } from '@/lib/i18n/core';

const CHIP = 'inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-none';

export function techniqueLabel(id: string, t: TFn): string {
  const tech = TECHNIQUES[id];
  if (!tech) return id;
  return langOf(t) === 'en' ? tech.en : tech.zh;
}

export function controlLabel(id: string, t: TFn): string {
  const fw = FRAMEWORKS.find((f) => f.id === frameworkOf(id));
  const c = CONTROLS[id];
  const num = id.split(':')[1] ?? id;
  const name = c ? (langOf(t) === 'en' ? c.en : c.zh) : '';
  return `${fw?.short ?? ''} ${num}${name ? ` ${name}` : ''}`.trim();
}

export function AttackTags({ mitre, compliance, t, base = '/findings' }: { mitre: string[]; compliance: string[]; t: TFn; base?: string }) {
  if (!mitre.length && !compliance.length) return null;
  const en = langOf(t) === 'en';
  return (
    <div className="flex flex-wrap items-center gap-1">
      {mitre.map((id) => {
        const tech = TECHNIQUES[id];
        const tactics = tech ? tech.tactics.map((x) => TACTICS.find((y) => y.id === x)).map((x) => (en ? x?.en : x?.zh)).join('、') : '';
        const tip = tech
          ? `MITRE ATT&CK ${id} ${en ? tech.en : tech.zh}${tactics ? `（${tactics}）` : ''}：${tech.hint}`
          : `MITRE ATT&CK ${id}`;
        return (
          <Tooltip key={id} text={tip}>
            <Link
              href={`${base}?technique=${encodeURIComponent(id)}`}
              className={`${CHIP} border-violet-300 text-violet-800 hover:bg-violet-50 dark:border-violet-700 dark:text-violet-300 dark:hover:bg-violet-950`}
            >
              {id}
            </Link>
          </Tooltip>
        );
      })}
      {compliance.map((id) => (
        <Tooltip key={id} text={`${controlLabel(id, t)} · ${t('參考對應，不等於稽核認證')}`}>
          <Link
            href={`${base}?control=${encodeURIComponent(id)}`}
            className={`${CHIP} border-slate-300 text-slate-600 hover:bg-slate-100 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-800`}
          >
            {id.replace('nist800-53', 'NIST').replace('iso27001', 'ISO').replace('pci4', 'PCI').replace('cis8', 'CIS')}
          </Link>
        </Tooltip>
      ))}
    </div>
  );
}
