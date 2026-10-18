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
    out.push(t('{h} 台主機碰到威脅情資列名的 IP 或網域，共 {n} 筆命中、{i} 個不同指標。', { h: r.intel.hosts, n: r.intel.hits, i: r.intel.indicators }));
  }
  if (r.connections.dangerous || r.connections.suspicious) {
    out.push(t('有 {d} 個危險、{s} 個可疑的遠端 IP。', { d: r.connections.dangerous, s: r.connections.suspicious }));
  }
  if (r.dns.alerts) out.push(t('DNS 告警 {n} 則（亂數網域、DNS 通道、黑名單網域等）。', { n: r.dns.alerts }));
  if (r.dns.blocked) out.push(t('防護 DNS 擋下 {n} 次查詢。', { n: r.dns.blocked }));
  if (r.events.total) out.push(t('資安事件 {n} 次，來自 {s} 個不同來源 IP。', { n: r.events.total, s: r.events.sources }));
  if (r.actions.autoBlocks) out.push(t('自動回應封鎖了 {n} 次。', { n: r.actions.autoBlocks }));
  const low = r.score.lowest[0];
  if (low && !r.agent) out.push(t('分數最低的主機是 {h}（{s} 分）。', { h: low.hostname, s: low.overall }));
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
