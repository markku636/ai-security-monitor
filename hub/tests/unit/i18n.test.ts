import { describe, expect, it } from 'vitest';
import { interpolate, resolveLang, translate } from '@/lib/i18n/core';
import { en } from '@/messages/en';

describe('i18n', () => {
  it('interpolates and keeps unknown placeholders', () => {
    expect(interpolate('正常（{ms} ms）', { ms: 3 })).toBe('正常（3 ms）');
    expect(interpolate('{a}-{b}', { a: 1 })).toBe('1-{b}');
  });

  it('falls back to the zh literal', () => {
    expect(translate('沒有收錄的字串', undefined, 'en')).toBe('沒有收錄的字串');
    expect(translate('登入', undefined, 'en')).toBe('Sign in');
    expect(translate('登入', undefined, 'zh-TW')).toBe('登入');
  });

  it('resolves language from cookie then Accept-Language', () => {
    expect(resolveLang('en', 'zh-TW')).toBe('en');
    expect(resolveLang(undefined, 'en-US,en;q=0.9')).toBe('en');
    expect(resolveLang(undefined, 'zh-TW,zh;q=0.9')).toBe('zh-TW');
    expect(resolveLang('fr', null)).toBe('zh-TW');
  });

  it('every English template keeps the same placeholders', () => {
    for (const [zh, e] of Object.entries(en)) {
      const ph = (s: string) => [...s.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();
      expect(ph(e), zh).toEqual(ph(zh));
    }
  });
});
