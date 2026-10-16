import type { Metadata } from 'next';
import { cookies } from 'next/headers';
import type { ReactNode } from 'react';
import { I18nProvider } from '@/lib/i18n/client';
import { THEME_COOKIE } from '@/lib/i18n/core';
import { getT } from '@/lib/i18n/server';
import './globals.css';

export async function generateMetadata(): Promise<Metadata> {
  const { t } = await getT();
  return {
    title: 'Security Hub',
    description: t('ai-security-agent 的中央儀表板：連線判定、威脅情資、防火牆、漏洞與 AI 分析'),
  };
}

// 沒選過主題（或選「跟隨系統」）時，在第一次繪製前依系統深色設定加上 .dark，避免閃白。
const SYSTEM_THEME = "try{if(matchMedia('(prefers-color-scheme: dark)').matches)document.documentElement.classList.add('dark')}catch(e){}";

export default async function RootLayout({ children }: { children: ReactNode }) {
  const { lang } = await getT();
  const theme = (await cookies()).get(THEME_COOKIE)?.value;
  return (
    <html lang={lang} className={theme === 'dark' ? 'dark' : undefined} suppressHydrationWarning>
      <head>{theme === 'dark' || theme === 'light' ? null : <script dangerouslySetInnerHTML={{ __html: SYSTEM_THEME }} />}</head>
      <body className="min-h-screen font-sans">
        <I18nProvider lang={lang}>{children}</I18nProvider>
      </body>
    </html>
  );
}
