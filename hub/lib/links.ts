// 主機（agent）送來的網址（情資來源、參考資料）只當 https 連結顯示；其他協定（http、data:、javascript:…）不給點。
export function httpsHref(url: string | null | undefined): string | undefined {
  return url && /^https:\/\//i.test(url.trim()) ? url.trim() : undefined;
}
