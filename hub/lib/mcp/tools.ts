// Hub MCP 工具：全部唯讀，直接重用 lib/queries（「AI 看到的＝畫面顯示的」）。
import fs from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';
import { listActions } from '@/lib/actions/store';
import { ipContext } from '@/lib/ai/context';
import { getDb } from '@/lib/db';
import { feedsDir, loadRegistry } from '@/lib/intel/registry';
import { averageScore, fleetSummary, listAgents } from '@/lib/queries/agents';
import { connectionStats } from '@/lib/queries/connection-stats';
import { inboundAttackers, listConnections, parseConnectionFilter } from '@/lib/queries/connections';
import { bruteForceSources, recentCrashes, securityHits, topBugchecks } from '@/lib/queries/events';
import { listFindings, parseFindingFilter, toFindingView } from '@/lib/queries/findings';
import { feedHitStats, lookupIndicator } from '@/lib/queries/intel';
import { agentHardening, agentVuln, hardeningOverview, vulnOverview } from '@/lib/queries/posture';
import { bandwidthSeries, hostPerfSeries, hostTrafficRanking, interfaceBreakdown, latestPerf, parseRange, perfAlerts, processTraffic, trafficSummary } from '@/lib/queries/metrics';
import { getAgent } from '@/lib/queries/agents';
import { processActivity, topDestinations } from '@/lib/queries/traffic';
import { dnsDigest, domainDetail, normalizeDomain, recentQueries } from '@/lib/queries/dns';

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const obj = (properties: Record<string, unknown>, required: string[] = []) => ({ type: 'object', properties, required, additionalProperties: false });
const days = { type: 'integer', minimum: 1, maximum: 90 };
const agent = { type: 'string', description: 'agent id (see list_agents)' };

export const TOOLS: ToolDef[] = [
  { name: 'fleet_summary', description: 'Fleet overview: agents online/stale/offline, open findings by severity, dangerous/suspicious connections, average security scores, intel feeds with hits in the last 7 days.', inputSchema: obj({}) },
  { name: 'list_agents', description: 'All enrolled agents (hosts) with OS, version, status, score and open finding counts.', inputSchema: obj({}) },
  {
    name: 'list_findings',
    description: 'Findings across the fleet (or one agent). Default: open and acknowledged. Includes rule, severity, recommendation and intel sources (vendor, confidence, source_url).',
    inputSchema: obj({
      agent_id: agent,
      severity: { type: 'array', items: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] } },
      status: { type: 'array', items: { type: 'string', enum: ['open', 'acked', 'suppressed', 'resolved'] } },
      q: { type: 'string' },
      limit: { type: 'integer', minimum: 1, maximum: 200 },
    }),
  },
  {
    name: 'list_connections',
    description: 'Current connections from the latest snapshot of each agent, with direction, verdict and reasons (intel hits cite vendor and source_url).',
    inputSchema: obj({
      agent_id: agent,
      direction: { type: 'array', items: { type: 'string', enum: ['outbound', 'inbound', 'listening', 'local'] } },
      verdict: { type: 'array', items: { type: 'string', enum: ['dangerous', 'suspicious', 'unknown', 'safe'] } },
      q: { type: 'string', description: 'IP, process, organization or hostname' },
      limit: { type: 'integer', minimum: 1, maximum: 200 },
    }),
  },
  {
    name: 'connection_stats',
    description: 'Counts of current connections (no need to count yourself): total, plus counts grouped by verdict, direction, state, protocol, process, country, remote port, remote IP and host (top 15 each). Optionally filter by agent, direction and verdict.',
    inputSchema: obj({
      agent_id: agent,
      direction: { type: 'array', items: { type: 'string', enum: ['outbound', 'inbound', 'listening', 'local'] } },
      verdict: { type: 'array', items: { type: 'string', enum: ['dangerous', 'suspicious', 'unknown', 'safe'] } },
    }),
  },
  { name: 'inbound_attackers', description: 'Remote IPs currently connected inbound and rated suspicious/dangerous, aggregated across hosts.', inputSchema: obj({}) },
  { name: 'lookup_indicator', description: 'Where an IP or domain shows up in the fleet: intel feeds that listed it, current connections, history. For an IP also the operator note and cached external threat intel (risk score, AbuseIPDB/GreyNoise/etc.; read from cache only, never queried live).', inputSchema: obj({ q: { type: 'string' } }, ['q']) },
  { name: 'top_destinations', description: 'Most contacted destinations (optionally only suspicious/dangerous) and per-process connection counts.', inputSchema: obj({ days, risky: { type: 'boolean' }, agent_id: agent }) },
  { name: 'crash_history', description: 'Blue screens, unexpected shutdowns, app crashes, service failures, disk/hardware errors with likely causes; plus the most common bugcheck codes.', inputSchema: obj({ days, agent_id: agent }) },
  { name: 'security_events', description: 'Security events from host logs: brute force, remote logons from the internet, new accounts/admins, new services, scheduled tasks, cleared logs, Defender.', inputSchema: obj({ days, agent_id: agent, rule: { type: 'string' } }) },
  { name: 'brute_force_sources', description: 'Failed-logon brute-force source IPs aggregated across hosts, with intel hits.', inputSchema: obj({ days }) },
  { name: 'explain_bugcheck', description: 'Name, likely causes and fixes for a Windows bugcheck code such as 0x7E or 0x124.', inputSchema: obj({ code: { type: 'string' } }, ['code']) },
  { name: 'list_actions', description: 'Remote defensive actions (block IP, close port) and their review status and results.', inputSchema: obj({ status: { type: 'array', items: { type: 'string' } } }) },
  {
    name: 'vuln_overview',
    description:
      'Vulnerabilities and updates: OS support lifetime (end-of-life dates), last patch / pending security updates, software on known-vulnerable versions with CVEs and CISA KEV, OSV results for Linux packages. Fleet-wide, or one host with agent_id.',
    inputSchema: obj({ agent_id: agent }),
  },
  {
    name: 'hardening_overview',
    description:
      'System hardening checks (UAC, antivirus, disk encryption, SSH, kernel settings, automatic updates, ...): per-host scores and the most common failures, or one host\'s check results with current value, fix and references (agent_id).',
    inputSchema: obj({ agent_id: agent, only_failed: { type: 'boolean' } }),
  },
  {
    name: 'fleet_traffic',
    description:
      'Network traffic volume (bytes, not packets) reported every minute by each host: fleet upload/download totals and average rates for the range, hosts ranked by traffic (24 h and 7 days), per-interface totals (virtual adapters such as VPN/Docker/WSL are flagged and not counted in totals) and per-process bytes where the host can measure them (Windows running as administrator, macOS). Optional agent_id narrows it to one host.',
    inputSchema: obj({ range: { type: 'string', enum: ['1h', '24h', '7d', '30d'] }, agent_id: agent }),
  },
  {
    name: 'host_performance',
    description:
      'Performance metrics (CPU, memory, disk usage and I/O, network rate, top processes by CPU/memory, battery) for one host over a range; only available when the host itself turned performance collection on (the hub cannot enable it). Without agent_id: hosts whose latest CPU, memory or disk usage is at or above 90%.',
    inputSchema: obj({ agent_id: agent, range: { type: 'string', enum: ['1h', '24h', '7d', '30d'] } }),
  },
  {
    name: 'dns_overview',
    description:
      'DNS monitoring across the fleet (or one agent): lookup totals and NXDOMAIN share for the range, most-queried registrable domains, domains first seen in the fleet in the last 24 h, and open DNS findings (threat-intel domains, DNS tunneling, DGA, NXDOMAIN bursts, DoH bypass, reverse tunnel services).',
    inputSchema: obj({ days, agent_id: agent }),
  },
  {
    name: 'dns_queries',
    description:
      'Recent DNS lookups (raw per-minute records, newest first, kept about 7 days): host, process, name, type, result (NOERROR/NXDOMAIN/…), count and resolved IPs. Filter by agent_id, a substring of the domain or process (q) and nxdomain_only.',
    inputSchema: obj({ agent_id: agent, q: { type: 'string' }, nxdomain_only: { type: 'boolean' }, limit: { type: 'integer', minimum: 1, maximum: 200 } }),
  },
  {
    name: 'domain_summary',
    description:
      'One domain (or registrable domain) across the fleet: which hosts and processes looked it up, result codes, resolved IPs, full names seen, hourly counts for 7 days, first/last seen in the fleet and related DNS findings. Use lookup_indicator for threat-intel hits on the domain.',
    inputSchema: obj({ domain: { type: 'string' } }, ['domain']),
  },
  { name: 'intel_feeds', description: 'Threat-intel sources used by the agents: vendor, license (commercial use, attribution), confidence and 7-day hits.', inputSchema: obj({}) },
];

export const MAX_TEXT = 60 * 1024;

export function toText(v: unknown): string {
  const s = JSON.stringify(v, null, 2);
  return s.length <= MAX_TEXT ? s : `${s.slice(0, MAX_TEXT)}\n… (truncated, ${s.length} chars total)`;
}

const str = (a: Record<string, unknown>, k: string) => (typeof a[k] === 'string' && (a[k] as string).trim() ? (a[k] as string).trim() : undefined);
const num = (a: Record<string, unknown>, k: string, d: number, max: number) => {
  const n = Number(a[k]);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), max) : d;
};
const list = (a: Record<string, unknown>, k: string) => (Array.isArray(a[k]) ? (a[k] as unknown[]).filter((x): x is string => typeof x === 'string').join(',') : undefined);

function parseCode(s: string): number | null {
  const t = s.trim().split(/[\s(,]/)[0];
  if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  if (/^[0-9]+$/.test(t)) return parseInt(t, 10);
  if (/^[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  return null;
}

export async function callTool(name: string, args: Record<string, unknown>): Promise<string> {
  switch (name) {
    case 'fleet_summary': {
      const [fleet, agents, feeds] = await Promise.all([fleetSummary(), listAgents(), feedHitStats(7)]);
      return toText({ ...fleet, score: averageScore(agents), intel_feeds_7d: [...feeds.values()] });
    }
    case 'list_agents': {
      const rows = await listAgents();
      return toText(
        rows.map((a) => ({
          id: a.id,
          hostname: a.hostname,
          os: [a.osName ?? a.osFamily, a.osVersion].filter(Boolean).join(' '),
          version: a.version,
          status: a.status,
          elevated: a.elevated,
          score: a.score,
          open_findings: a.openFindings,
          sev_counts: a.sevCounts,
          last_seen_at: a.lastSeenAt,
          accepts_remote_actions: a.acceptRemoteActions,
        })),
      );
    }
    case 'list_findings': {
      const f = parseFindingFilter({ agent_id: str(args, 'agent_id'), severity: list(args, 'severity'), status: list(args, 'status'), q: str(args, 'q'), limit: String(num(args, 'limit', 50, 200)) });
      const r = await listFindings(f);
      return toText({ total: r.total, facets: r.facets, items: r.items.map(toFindingView) });
    }
    case 'list_connections': {
      const f = parseConnectionFilter({ agent_id: str(args, 'agent_id'), direction: list(args, 'direction'), verdict: list(args, 'verdict'), q: str(args, 'q'), limit: String(num(args, 'limit', 50, 200)) });
      const r = await listConnections(f);
      return toText({ total: r.total, facets: r.facets, items: r.items });
    }
    case 'connection_stats':
      return toText(await connectionStats({ agentId: str(args, 'agent_id'), direction: list(args, 'direction')?.split(',').filter(Boolean), verdict: list(args, 'verdict')?.split(',').filter(Boolean) }));
    case 'inbound_attackers':
      return toText(await inboundAttackers(30));
    case 'lookup_indicator': {
      const q = str(args, 'q');
      if (!q) throw new Error('q is required');
      const base = await lookupIndicator(q);
      if (!isIP(q)) return toText({ q, ...base });
      const c = await ipContext(q);
      return toText({ q, ...base, note: c.note, external_intel: c.external_intel });
    }
    case 'top_destinations': {
      const d = num(args, 'days', 7, 90);
      const agentId = str(args, 'agent_id');
      const [dest, procs] = await Promise.all([topDestinations({ days: d, agentId, risky: args.risky === true, limit: 50 }), processActivity(agentId, 20)]);
      return toText({ destinations: dest, processes: procs });
    }
    case 'crash_history': {
      const d = num(args, 'days', 30, 90);
      const agentId = str(args, 'agent_id');
      const [crashes, bugs] = await Promise.all([recentCrashes({ days: d, agentId, limit: 100 }), topBugchecks(d, 10)]);
      return toText({ days: d, top_bugchecks: bugs, crashes });
    }
    case 'security_events': {
      const rule = str(args, 'rule');
      return toText(await securityHits({ days: num(args, 'days', 30, 90), agentId: str(args, 'agent_id'), rules: rule ? [rule] : undefined, limit: 100 }));
    }
    case 'brute_force_sources':
      return toText(await bruteForceSources(num(args, 'days', 30, 90), 30));
    case 'explain_bugcheck': {
      const code = parseCode(str(args, 'code') ?? '');
      if (code === null) throw new Error('code must look like 0x7E or 126');
      const dir = feedsDir();
      if (!dir) throw new Error('feeds directory not found');
      const table = JSON.parse(fs.readFileSync(path.join(dir, 'events', 'bugchecks.json'), 'utf8')) as { bugchecks: { code: string }[] };
      const hit = table.bugchecks.find((b) => parseCode(b.code) === code);
      if (!hit) throw new Error(`no entry for 0x${code.toString(16).toUpperCase().padStart(8, '0')}`);
      return toText(hit);
    }
    case 'list_actions': {
      const status = Array.isArray(args.status) ? (args.status as string[]) : undefined;
      const r = await listActions(getDb(), { status: status as never, limit: 100 });
      return toText(r);
    }
    case 'vuln_overview': {
      const agentId = str(args, 'agent_id');
      if (agentId) return toText((await agentVuln(agentId)) ?? { error: 'no vulnerability summary for this agent' });
      const v = await vulnOverview();
      return toText({ ...v, apps: v.apps.slice(0, 50), os: v.os.slice(0, 200), patches: v.patches.slice(0, 200) });
    }
    case 'hardening_overview': {
      const agentId = str(args, 'agent_id');
      if (agentId) {
        const h = await agentHardening(agentId);
        if (!h) return toText({ error: 'no hardening summary for this agent' });
        const onlyFailed = args.only_failed === true;
        return toText({ at: h.at, summary: { ...h.summary, results: h.summary.results.filter((o) => !onlyFailed || o.result === 'fail') } });
      }
      const h = await hardeningOverview();
      return toText({ average: h.average, hosts: h.hosts, top_failed: h.topFailed.slice(0, 40).map((e) => ({ id: e.check.id, title: e.check.title, severity: e.check.severity, remediation: e.check.remediation, failed: e.hosts.length, checked: e.checked, hosts: e.hosts.map((x) => x.hostname) })) });
    }
    case 'fleet_traffic': {
      const range = parseRange({ range: str(args, 'range') });
      const agentId = str(args, 'agent_id');
      const [bw, hosts, ifaces, procs, summary] = await Promise.all([
        bandwidthSeries(range, agentId),
        agentId ? Promise.resolve([]) : hostTrafficRanking(20),
        interfaceBreakdown(range, agentId, 30),
        processTraffic(range, agentId, 15),
        trafficSummary(),
      ]);
      const pts = bw.points.filter((p) => p.rx != null);
      const peak = (k: 'rx' | 'tx') => pts.reduce((m, p) => Math.max(m, p[k] ?? 0), 0);
      return toText({
        range,
        unit: 'bytes; rates in bytes per second averaged over each bucket',
        totals: { rx_bytes: bw.totalRx, tx_bytes: bw.totalTx, peak_rx_bytes_per_s: peak('rx'), peak_tx_bytes_per_s: peak('tx'), bucket_s: bw.bucketS },
        fleet_24h: agentId ? undefined : summary,
        hosts: hosts.map((h) => ({ agent_id: h.agentId, hostname: h.hostname, rx_24h: h.rx24h, tx_24h: h.tx24h, rx_7d: h.rx7d, tx_7d: h.tx7d })),
        interfaces: ifaces,
        processes: procs.rows,
        processes_note: procs.hostsWithData < procs.hostsTotal ? `${procs.hostsTotal - procs.hostsWithData} host(s) cannot measure per-process bytes (Linux without eBPF, or Windows not running as administrator); use top_destinations for per-process connection counts` : undefined,
      });
    }
    case 'host_performance': {
      const agentId = str(args, 'agent_id');
      const range = parseRange({ range: str(args, 'range') });
      if (!agentId) return toText({ threshold_pct: 90, hosts_over_threshold: await perfAlerts() });
      const a = await getAgent(agentId);
      if (!a) throw new Error('unknown agent_id');
      const [series, latest] = await Promise.all([hostPerfSeries(agentId, range), latestPerf(agentId)]);
      const vals = (k: 'cpu' | 'memPct' | 'diskPct') => series.points.map((p) => p[k]).filter((v): v is number => v != null);
      const avg = (v: number[]) => (v.length ? v.reduce((x, y) => x + y, 0) / v.length : null);
      const max = (v: number[]) => (v.length ? Math.max(...v) : null);
      return toText({
        hostname: a.hostname,
        performance_enabled: a.perfEnabled === true,
        note: a.perfEnabled === true ? undefined : 'performance collection is off on this host (the host owner can enable it: ai-security-monitor config set metrics.performance true, or the desktop app Settings); only network traffic is available',
        range,
        series: {
          samples: series.points.filter((p) => p.rx != null || p.cpu != null).length,
          bucket_s: series.bucketS,
          cpu_avg_pct: avg(vals('cpu')),
          cpu_max_pct: max(series.points.map((p) => p.cpuMax).filter((v): v is number => v != null)),
          mem_max_pct: max(vals('memPct')),
          disk_max_pct: max(vals('diskPct')),
          rx_peak_bytes_per_s: max(series.points.map((p) => p.rx).filter((v): v is number => v != null)),
          tx_peak_bytes_per_s: max(series.points.map((p) => p.tx).filter((v): v is number => v != null)),
        },
        latest,
      });
    }
    case 'dns_overview':
      return toText(await dnsDigest(num(args, 'days', 1, 90), str(args, 'agent_id')));
    case 'dns_queries':
      return toText(
        await recentQueries({
          agentId: str(args, 'agent_id'),
          q: str(args, 'q'),
          nx: args.nxdomain_only === true,
          limit: num(args, 'limit', 50, 200),
        }),
      );
    case 'domain_summary': {
      const d = normalizeDomain(str(args, 'domain') ?? '');
      if (!d) return toText({ error: 'invalid domain' });
      return toText({ query: d, ...(await domainDetail(d)) });
    }
    case 'intel_feeds': {
      const stats = await feedHitStats(7);
      return toText(
        loadRegistry().map((f) => ({
          id: f.id,
          vendor: f.vendor,
          name: f.name,
          kind: f.kind,
          confidence: f.confidence,
          license: f.license,
          url: f.urls[0],
          hits_7d: stats.get(f.id) ?? null,
        })),
      );
    }
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}
