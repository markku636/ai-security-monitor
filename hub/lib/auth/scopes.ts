// API token 的 scope（不含 node 模組：設定頁的 client 元件也直接用這份，不要再複製一份清單）。
//   read     讀取 API（/api/v1/…）
//   export   CSV 匯出
//   mcp      Hub MCP（/api/mcp）
//   dns      防護 DNS 伺服器：拉設定、送心跳與查詢紀錄
//   webscan  網站掃描端（webscan runner）：認領掃描工作、上傳原始輸出與結果
export const TOKEN_SCOPES = ['read', 'export', 'mcp', 'dns', 'webscan'] as const;
export type TokenScope = (typeof TOKEN_SCOPES)[number];
