'use client';

import { createContext, useContext, useMemo, type ReactNode } from 'react';
import { makeT, type Lang, type TFn } from './core';

const Ctx = createContext<{ lang: Lang; t: TFn }>({ lang: 'zh-TW', t: makeT('zh-TW') });

export function I18nProvider({ lang, children }: { lang: Lang; children: ReactNode }) {
  const value = useMemo(() => ({ lang, t: makeT(lang) }), [lang]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useT(): { lang: Lang; t: TFn } {
  return useContext(Ctx);
}
