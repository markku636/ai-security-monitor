// 選單圖示（內嵌 SVG，24×24 線條，跟著文字顏色）。
const PATHS = {
  home: 'M3 11.5 12 4l9 7.5M5 10v10h5v-6h4v6h5V10',
  hosts: 'M4 5h16v10H4zM2 19h20M9 15v4M15 15v4',
  add: 'M12 5v14M5 12h14',
  alert: 'M12 3 2 20h20L12 3zM12 10v4M12 17h.01',
  block: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM5.6 5.6l12.8 12.8',
  network: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9M12 3C9.5 5.6 8.2 8.6 8.2 12s1.3 6.4 3.8 9',
  traffic: 'M3 17l5-5 4 4 8-8M15 8h5v5',
  intel: 'M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6l-8-3zM9 12l2 2 4-4',
  bug: 'M9 7V5a3 3 0 0 1 6 0v2M6 10h12v4a6 6 0 0 1-12 0v-4zM3 12h3M18 12h3M4 18l2.5-1.5M20 18l-2.5-1.5M12 10v10',
  settingsCheck: 'M9 4h6l1 2h3v14H5V6h3l1-2zM9 13l2 2 4-4',
  matrix: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  dns: 'M4 5h16v5H4zM4 14h16v5H4zM7.5 7.5h.01M7.5 16.5h.01M11 7.5h6M11 16.5h6',
  event: 'M4 5h16v14H4zM4 9h16M8 3v4M16 3v4M12 13v3M12 18h.01',
  ai: 'M12 3l1.8 4.2L18 9l-4.2 1.8L12 15l-1.8-4.2L6 9l4.2-1.8L12 3zM18 15l.9 2.1L21 18l-2.1.9L18 21l-.9-2.1L15 18l2.1-.9L18 15z',
  key: 'M14 4a6 6 0 1 0 0 12 6 6 0 0 0 0-12zM9.8 14.2 3 21M6 18l2 2M14 8h.01',
  menu: 'M4 6h16M4 12h16M4 18h16',
  close: 'M6 6l12 12M18 6 6 18',
} as const;

export type IconName = keyof typeof PATHS;

export function NavIcon({ name, className = 'h-5 w-5' }: { name: IconName; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={PATHS[name]} />
    </svg>
  );
}
