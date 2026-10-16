// 測試用的假 `claude -p --output-format stream-json`：檢查 hub 給的參數與 MCP 設定，印出一段固定的事件串流。
import fs from 'node:fs';

const argv = process.argv.slice(2);
const at = (flag) => argv[argv.indexOf(flag) + 1];
const stdin = fs.readFileSync(0, 'utf8');
const cfg = JSON.parse(fs.readFileSync(at('--mcp-config'), 'utf8'));
const srv = cfg.mcpServers.asahub;
const out = (o) => process.stdout.write(JSON.stringify(o) + '\n');
// 白名單 env：hub 的金鑰不該出現在子行程
const leaked = ['ASA_HUB_ADMIN_SECRET', 'ASA_HUB_DATABASE_URL', 'ASA_HUB_CLIENT_SECRETS'].filter((k) => process.env[k]);
out({ type: 'system', subtype: 'init', model: 'fake' });
out({ type: 'assistant', message: { content: [{ type: 'tool_use', id: 't1', name: 'mcp__asahub__fleet_summary', input: {} }] } });
out({ type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 't1', content: [{ type: 'text', text: '{"agents":{"total":1}}' }] }] } });
const text = `ok url=${srv.url} auth=${String(srv.headers.Authorization).startsWith('Bearer ')} type=${srv.type} allowed=${at('--allowedTools').split(',').length} leaked=${leaked.length} strict=${argv.includes('--strict-mcp-config')} prompt=${stdin.slice(0, 20)}`;
out({ type: 'stream_event', event: { type: 'content_block_delta', delta: { type: 'text_delta', text } } });
// env 會被白名單擋掉，所以用 prompt 裡的標記要求卡住
if (stdin.includes('__HANG__')) {
  setInterval(() => {}, 1000);
} else {
  out({ type: 'result', is_error: false, result: text, duration_ms: 5 });
}
