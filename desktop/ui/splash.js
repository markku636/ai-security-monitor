// 啟動畫面：顯示約 1 秒後淡出並移除；系統設定減少動態效果時 CSS 直接隱藏。
(() => {
  const el = document.getElementById('splash');
  if (!el) return;
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) {
    el.remove();
    return;
  }
  setTimeout(() => {
    el.classList.add('hide');
    setTimeout(() => el.remove(), 400);
  }, 1000);
})();
