'use client';

// 列印／存成 PDF：列印時暫時切成淺色（深色背景印出來很吃墨也看不清楚），印完再切回來。
import { useT } from '@/lib/i18n/client';

export function PrintButton() {
  const { t } = useT();
  return (
    <button
      type="button"
      onClick={() => {
        const html = document.documentElement;
        const dark = html.classList.contains('dark');
        if (dark) {
          html.classList.remove('dark');
          window.addEventListener('afterprint', () => html.classList.add('dark'), { once: true });
        }
        window.print();
      }}
      className="rounded-md bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-700"
    >
      {t('列印／存成 PDF')}
    </button>
  );
}
