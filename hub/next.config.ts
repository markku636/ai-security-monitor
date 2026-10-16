import type { NextConfig } from 'next';
import path from 'node:path';

const config: NextConfig = {
  output: 'standalone',
  // 讓 standalone 輸出也追蹤到 repo 根目錄的 feeds/（情資登錄、bugcheck 表）。
  outputFileTracingRoot: path.join(__dirname, '..'),
  outputFileTracingIncludes: { '/**': ['./drizzle/**', '../feeds/**'] },
  serverExternalPackages: ['pg', '@electric-sql/pglite'],
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Content-Security-Policy', value: "frame-ancestors 'none'" },
        ],
      },
    ];
  },
};

export default config;
