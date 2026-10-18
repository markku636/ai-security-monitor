// 資安報告下載：GET ?from=YYYY-MM-DD&to=YYYY-MM-DD[&agent_id=][&format=md|json][&lang=en|zh-TW]（管理員或 read 權杖）。
import { apiRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error, json, parseCookies } from '@/lib/http';
import { LANG_COOKIE, makeT, resolveLang } from '@/lib/i18n/core';
import { buildReport, parsePeriod } from '@/lib/report/build';
import { periodText, toMarkdown } from '@/lib/report/text';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const u = new URL(req.url);
  const period = parsePeriod(u.searchParams.get('from') ?? undefined, u.searchParams.get('to') ?? undefined);
  if (!period) return error(400, 'bad_period');
  const agentId = u.searchParams.get('agent_id')?.trim().slice(0, 64) || null;
  const r = await buildReport(getDb(), { ...period, agentId });
  if (u.searchParams.get('format') === 'json') return json(r);
  // 語言：?lang=en|zh-TW ＞ cookie ＞ Accept-Language
  const q = u.searchParams.get('lang');
  const t = makeT(resolveLang(q === 'en' || q === 'zh-TW' ? q : parseCookies(req)[LANG_COOKIE], req.headers.get('accept-language')));
  const p = periodText(r);
  const name = `security-report-${p.from}_${p.to}${r.agent ? `-${r.agent.hostname.replace(/[^A-Za-z0-9._-]/g, '_')}` : ''}.md`;
  return new Response(toMarkdown(r, t), {
    headers: { 'content-type': 'text/markdown; charset=utf-8', 'content-disposition': `attachment; filename="${name}"`, 'cache-control': 'no-store' },
  });
}
