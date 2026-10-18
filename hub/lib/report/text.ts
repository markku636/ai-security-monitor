// 資安報告的文字：重點摘要（白話一句一點）與 Markdown 匯出。頁面與下載 API 共用。
import type { TFn } from '@/lib/i18n/core';
import { SEVERITIES, sevTotal, type SecurityReport, type Sev } from './build';

export function sevLabel(t: TFn, s: Sev): string {
  return { critical: t('嚴重'), high: t('高'), medium: t('中'), low: t('低'), info: t('資訊') }[s];
}

/** 區間顯示用（迄日含當天）。 */
export function periodText(r: SecurityReport): { from: string; to: string } {
  return { from: r.from.slice(0, 10), to: new Date(Date.parse(r.to) - 86_400_000).toISOString().slice(0, 10) };
}

/** 自動整理的重點（只講有發生的事）。 */
export function highlights(r: SecurityReport, t: TFn): string[] {
  const out: string[] = [];
  const nNew = sevTotal(r.findings.newBySev);
  const nRes = sevTotal(r.findings.resolvedBySev);
  const nOpen = sevTotal(r.findings.openEndBySev);
  const crit = r.findings.newBySev.critical + r.findings.newBySev.high;
  out.push(
    t('期間內新增 {n} 個問題（嚴重＋高 {c} 個），處理掉 {r} 個，期末還有 {o} 個待處理。', { n: nNew, c: crit, r: nRes, o: nOpen }),
  );
  if (r.score.start != null && r.score.end != null) {
    const d = Math.round((r.score.end - r.score.start) * 10) / 10;
    out.push(
      d === 0
        ? t('平均安全分數維持在 {s}。', { s: r.score.end })
        : d > 0
          ? t('平均安全分數從 {a} 進步到 {b}（+{d}）。', { a: r.score.start, b: r.score.end, d })
          : t('平均安全分數從 {a} 退步到 {b}（{d}）。', { a: r.score.start, b: r.score.end, d }),
    );
  }
  if (r.intel.hits) {
    out.push(t('{h} 台主機連到被資安單位列入黑名單（威脅情資）的 IP 或網域，共 {n} 次、{i} 個不同位址。', { h: r.intel.hosts, n: r.intel.hits, i: r.intel.indicators }));
  }
  if (r.connections.dangerous || r.connections.suspicious) {
    out.push(t('有 {d} 個危險、{s} 個可疑的連線對象（電腦連到或被連進來的外部位址）。', { d: r.connections.dangerous, s: r.connections.suspicious }));
  }
  if (r.dns.alerts) out.push(t('查網址（DNS）時的告警 {n} 則：例如連去黑名單網域、看起來是惡意程式亂產生的網域，或把資料藏在網址裡偷傳（DNS 通道）。', { n: r.dns.alerts }));
  if (r.dns.blocked) out.push(t('防護 DNS 擋下 {n} 次連往危險網站的查詢（擋下＝沒連上，已經保護到）。', { n: r.dns.blocked }));
  if (r.events.total) out.push(t('資安事件 {n} 次（例如有人一直試密碼登入、新增帳號、清掉紀錄），來自 {s} 個不同來源 IP。', { n: r.events.total, s: r.events.sources }));
  if (r.actions.autoBlocks) out.push(t('自動回應封鎖了 {n} 次。', { n: r.actions.autoBlocks }));
  const low = r.score.lowest[0];
  if (low && !r.agent) out.push(t('分數最低的主機是 {h}（{s} 分）。', { h: low.hostname, s: low.overall }));
  return out;
}

/** 一句話結論：整體要不要擔心。 */
export function verdict(r: SecurityReport, t: TFn): { tone: 'ok' | 'warn' | 'bad'; text: string } {
  const open = r.findings.openEndBySev;
  const urgent = open.critical + open.high;
  if (open.critical > 0 || r.connections.dangerous > 0) {
    return { tone: 'bad', text: t('有需要盡快處理的事：{c} 個嚴重或高風險問題還沒處理、{d} 個危險的連線對象。請先看下面「建議你先做」。', { c: urgent, d: r.connections.dangerous }) };
  }
  if (urgent > 0 || r.connections.suspicious > 0 || r.dns.alerts > 0 || r.events.total > 0) {
    return { tone: 'warn', text: t('沒有緊急狀況，但有幾件事值得這週看一下。') };
  }
  if (r.hosts.total > 0 && r.hosts.reporting === 0) {
    return { tone: 'warn', text: t('這段期間沒有主機回報資料，所以報告是空的；請確認各台電腦的背景服務有在執行。') };
  }
  return { tone: 'ok', text: t('這段期間整體狀況良好，沒有需要處理的事。') };
}

/** 建議你先做（依急迫程度；只列有發生的）。 */
export function todo(r: SecurityReport, t: TFn): string[] {
  const out: string[] = [];
  const open = r.findings.openEndBySev;
  if (r.connections.dangerous > 0) out.push(t('看「連線 → 可疑 IP 清單」裡判定「危險」的位址，確認是哪個程式在連；不認得就在「封鎖審核」核准封鎖。'));
  if (open.critical + open.high > 0) out.push(t('到「待處理問題」篩選「嚴重」「高」，依每一項的「建議」處理（{n} 個）。', { n: open.critical + open.high }));
  if (r.events.total > 0) out.push(t('看「當機與事件」的資安事件：有人一直試密碼的來源 IP 可以封鎖，不認得的新帳號要停用。'));
  if (r.dns.alerts > 0) out.push(t('看「DNS」頁的告警，確認是哪台電腦、哪個程式查了可疑網域。'));
  if (r.connections.suspicious > 0 && r.connections.dangerous === 0) out.push(t('「可疑」的連線對象可以用「查詢全部未分析」查外部情資，多半是誤報，確認後加備註即可。'));
  if (r.hosts.reporting < r.hosts.total) out.push(t('{n} 台主機這段期間沒有回報，確認它們有開機、背景服務有在執行。', { n: r.hosts.total - r.hosts.reporting }));
  if (open.medium + open.low > 0 && open.critical + open.high === 0) out.push(t('有空時處理「中」「低」風險的問題（{n} 個），多半是設定建議。', { n: open.medium + open.low }));
  return out;
}

const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');

function table(head: string[], rows: (string | number)[][]): string {
  if (!rows.length) return '';
  return [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.map((c) => esc(String(c))).join(' | ')} |`)].join('\n') + '\n';
}

export function toMarkdown(r: SecurityReport, t: TFn): string {
  const p = periodText(r);
  const sevRow = (c: SecurityReport['findings']['newBySev']) => SEVERITIES.map((s) => c[s]);
  const parts: string[] = [];
  parts.push(`# ${t('資安報告')}${r.agent ? ` — ${r.agent.hostname}` : ''}`);
  parts.push(
    `${t('區間')}：${p.from} ～ ${p.to}（${t('{n} 天', { n: r.days })}）　${t('主機')}：${r.hosts.total}（${t('有回報 {n} 台', { n: r.hosts.reporting })}）　${t('產生時間')}：${r.generatedAt.slice(0, 16).replace('T', ' ')} UTC`,
  );
  parts.push(`## ${t('結論')}\n\n${verdict(r, t).text}`);
  const steps = todo(r, t);
  if (steps.length) parts.push(`## ${t('建議你先做')}\n\n${steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`);
  parts.push(`## ${t('重點')}\n\n${highlights(r, t).map((h) => `- ${h}`).join('\n')}`);
  parts.push(
    `## ${t('問題')}\n\n` +
      table([t('類型'), ...SEVERITIES.map((s) => sevLabel(t, s))], [
        [t('新增'), ...sevRow(r.findings.newBySev)],
        [t('已處理'), ...sevRow(r.findings.resolvedBySev)],
        [t('期末待處理'), ...sevRow(r.findings.openEndBySev)],
      ]) +
      (r.findings.topRules.length
        ? `\n### ${t('最常出現的問題')}\n\n` +
          table(
            [t('嚴重度'), t('問題'), t('規則'), t('次數'), t('主機')],
            r.findings.topRules.map((x) => [sevLabel(t, x.severity), x.title, x.rule, x.count, x.hosts]),
          )
        : '') +
      (r.findings.topNew.length
        ? `\n### ${t('新出現的嚴重與高風險問題')}\n\n` +
          table(
            [t('嚴重度'), t('主機'), t('問題'), t('第一次看到')],
            r.findings.topNew.map((x) => [sevLabel(t, x.severity), x.hostname, x.title, x.firstSeenAt.slice(0, 16).replace('T', ' ')]),
          )
        : ''),
  );
  if (r.score.lowest.length && !r.agent) {
    parts.push(`## ${t('分數最低的主機')}\n\n` + table([t('主機'), t('總分')], r.score.lowest.map((x) => [x.hostname, x.overall])));
  }
  parts.push(
    `## ${t('威脅情資與連線')}\n\n` +
      `${t('情資命中 {n} 筆（{i} 個指標、{h} 台主機）；危險 IP {d} 個、可疑 IP {s} 個。', { n: r.intel.hits, i: r.intel.indicators, h: r.intel.hosts, d: r.connections.dangerous, s: r.connections.suspicious })}\n\n` +
      table([t('來源'), t('命中')], r.intel.byFeed.map((x) => [`${x.vendor} ${x.feed}`, x.hits])) +
      (r.connections.topIps.length
        ? `\n` +
          table(
            [t('遠端 IP'), t('判定'), t('次數'), t('主機'), t('國家／組織'), t('程式'), t('備註')],
            r.connections.topIps.map((x) => [
              x.ip,
              x.verdict === 'dangerous' ? t('危險') : t('可疑'),
              x.seen,
              x.hosts,
              [x.country, x.org].filter(Boolean).join(' '),
              x.process ?? '',
              x.note ?? '',
            ]),
          )
        : ''),
  );
  parts.push(
    `## DNS\n\n${t('查詢 {q} 次、{d} 個不同網域、查無此網域 {nx} 次；DNS 告警 {a} 則；防護 DNS 擋下 {b} 次。', { q: r.dns.queries, d: r.dns.domains, nx: r.dns.nxdomain, a: r.dns.alerts, b: r.dns.blocked })}\n\n` +
      table([t('被擋最多的網域'), t('次數')], r.dns.topBlocked.map((x) => [x.domain, x.count])),
  );
  if (r.events.total) {
    parts.push(`## ${t('資安事件')}\n\n` + table([t('規則'), t('次數'), t('主機')], r.events.byRule.map((x) => [x.rule, x.count, x.hosts])));
  }
  if (r.actions.total || r.actions.autoBlocks) {
    parts.push(
      `## ${t('封鎖與遠端動作')}\n\n${t('遠端動作 {n} 筆、自動回應封鎖 {b} 次。', { n: r.actions.total, b: r.actions.autoBlocks })}\n\n` +
        table([t('動作'), t('狀態'), t('筆數')], r.actions.byKind.map((x) => [x.kind, x.status, x.count])),
    );
  }
  if (r.mitre.length) {
    parts.push(`## MITRE ATT&CK\n\n` + table([t('技術'), t('名稱'), t('問題數')], r.mitre.map((x) => [x.id, `${x.name}（${x.nameEn}）`, x.count])));
  }
  parts.push(`---\n${t('由 AI Security Monitor Security Hub 產生；對應 MITRE ATT&CK 與法規僅供參考，不等於稽核或認證。')}`);
  return parts.join('\n\n') + '\n';
}
