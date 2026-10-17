// 遠端 IP 的人工備註：GET ?ip= 讀、POST { ip, note } 寫（note 空字串＝刪除）。只有管理員。
import { isIP } from 'node:net';
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { error, json, readJson, sourceIp } from '@/lib/http';
import { getIpNote, NOTE_MAX, setIpNote } from '@/lib/queries/ipnotes';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  const ip = new URL(req.url).searchParams.get('ip')?.trim() ?? '';
  if (!isIP(ip)) return error(400, 'bad_ip');
  return json({ ip, note: await getIpNote(ip) });
}

const Body = z.object({
  ip: z.string().trim().max(64).refine((s) => isIP(s) !== 0),
  note: z.string().max(NOTE_MAX),
});

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 16 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const actor = actorOf(id);
  const note = await setIpNote(body.ip, body.note, actor);
  await audit({
    actor,
    actorRole: 'admin',
    action: note ? 'ip_note.set' : 'ip_note.delete',
    targetType: 'ip',
    targetId: body.ip,
    sourceIp: sourceIp(req),
    details: note ? { note: note.note.slice(0, 200) } : {},
  });
  return json({ ip: body.ip, note });
}
