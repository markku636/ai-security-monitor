// 寫入 DNS 查詢紀錄：(主機, 分鐘, 名稱, 類型, 結果, 程式, 來源) 唯一，重送（agent 的離線佇列）以新值覆蓋、不重複計算；
// 超過原始資料保留天數的列略過。順便更新全部主機看過的網域（第一次／最後一次出現）。
import { eq, sql } from 'drizzle-orm';
import { agents, dnsDomains, dnsQueries } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { env } from '@/lib/env';
import { IngestRejected } from '@/lib/ingest/guard';
import type { DnsBatchT } from '@/lib/ingest/schema';

export interface DnsResult {
  stored: number;
  stale: number;
  domains: number;
}

/** agent 沒帶可註冊網域時的退路：最後兩段（`a.b.example.com` → `example.com`）。 */
export function fallbackRegistrable(name: string): string {
  const parts = name.toLowerCase().replace(/\.$/, '').split('.');
  return parts.length <= 2 ? parts.join('.') : parts.slice(-2).join('.');
}

type Row = typeof dnsQueries.$inferInsert & { ts: Date; registrable: string; process: string };

export async function applyDns(db: DB, b: DnsBatchT, now = new Date()): Promise<DnsResult> {
  const [known] = await db.select({ deletedAt: agents.deletedAt }).from(agents).where(eq(agents.id, b.agent_id)).limit(1);
  if (!known) throw new IngestRejected(409, 'register_first');
  if (known.deletedAt) throw new IngestRejected(410, 'agent_deleted');
  const oldest = now.getTime() - env().dnsRawDays * 86_400_000;
  let stale = 0;
  const rows = new Map<string, Row>();
  for (const r of b.records) {
    let t = Date.parse(r.ts);
    if (t < oldest) {
      stale++;
      continue;
    }
    if (t > now.getTime()) t = now.getTime();
    const name = r.name.toLowerCase().replace(/\.$/, '');
    const process = r.process ?? '';
    rows.set([t, name, r.qtype, r.rcode, process, r.source].join('|'), {
      agentId: b.agent_id,
      ts: new Date(t),
      name,
      registrable: (r.registrable || fallbackRegistrable(name)).toLowerCase(),
      qtype: r.qtype,
      rcode: r.rcode,
      process,
      exe: r.exe ?? null,
      count: r.count,
      answers: r.answers,
      cnames: r.cnames,
      source: r.source,
      receivedAt: now,
    });
  }
  const list = [...rows.values()];
  for (let i = 0; i < list.length; i += 200) {
    await db
      .insert(dnsQueries)
      .values(list.slice(i, i + 200))
      .onConflictDoUpdate({
        target: [dnsQueries.agentId, dnsQueries.ts, dnsQueries.name, dnsQueries.qtype, dnsQueries.rcode, dnsQueries.process, dnsQueries.source],
        set: {
          count: sql`excluded.count`,
          answers: sql`excluded.answers`,
          cnames: sql`excluded.cnames`,
          exe: sql`excluded.exe`,
          receivedAt: now,
        },
      });
  }
  // 網域第一次／最後一次出現（一個可註冊網域一列）
  const doms = new Map<string, { first: Date; last: Date; process: string }>();
  for (const r of list) {
    const d = doms.get(r.registrable);
    if (!d) {
      doms.set(r.registrable, { first: r.ts, last: r.ts, process: r.process });
      continue;
    }
    if (r.ts < d.first) {
      d.first = r.ts;
      d.process = r.process;
    }
    if (r.ts > d.last) d.last = r.ts;
  }
  const domRows = [...doms].map(([registrable, d]) => ({
    registrable,
    firstSeenAt: d.first,
    lastSeenAt: d.last,
    firstAgentId: b.agent_id,
    firstProcess: d.process || null,
  }));
  for (let i = 0; i < domRows.length; i += 200) {
    await db
      .insert(dnsDomains)
      .values(domRows.slice(i, i + 200))
      .onConflictDoUpdate({
        target: dnsDomains.registrable,
        set: {
          lastSeenAt: sql`greatest(${dnsDomains.lastSeenAt}, excluded.last_seen_at)`,
          firstAgentId: sql`case when excluded.first_seen_at < ${dnsDomains.firstSeenAt} then excluded.first_agent_id else ${dnsDomains.firstAgentId} end`,
          firstProcess: sql`case when excluded.first_seen_at < ${dnsDomains.firstSeenAt} then excluded.first_process else ${dnsDomains.firstProcess} end`,
          firstSeenAt: sql`least(${dnsDomains.firstSeenAt}, excluded.first_seen_at)`,
        },
      });
  }
  await db.update(agents).set({ lastSeenAt: now }).where(eq(agents.id, b.agent_id));
  return { stored: list.length, stale, domains: domRows.length };
}
