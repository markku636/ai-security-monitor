// 通知頻道：設定驗證、祕密欄位加解密與遮罩、各種頻道的送出格式。
import { createHmac } from 'node:crypto';
import dgram from 'node:dgram';
import net from 'node:net';
import os from 'node:os';
import nodemailer from 'nodemailer';
import { z } from 'zod';
import { decrypt, encrypt, isEncrypted } from './secret';

export const CHANNEL_KINDS = ['email', 'slack', 'discord', 'teams', 'webhook', 'syslog'] as const;
export type ChannelKind = (typeof CHANNEL_KINDS)[number];

/** 各種頻道要加密的欄位。 */
export const SECRET_FIELDS: Record<ChannelKind, string[]> = {
  email: ['pass'],
  slack: ['url'],
  discord: ['url'],
  teams: ['url'],
  webhook: ['url', 'hmacSecret'],
  syslog: [],
};

const host = z.string().trim().min(1).max(253).regex(/^[A-Za-z0-9.:_-]+$/);
const port = z.coerce.number().int().min(1).max(65535);
const httpsUrl = z.string().trim().max(2000).url().refine((u) => u.startsWith('https://'), 'https only');
const httpUrl = z.string().trim().max(2000).url().refine((u) => /^https?:\/\//.test(u), 'http(s) only');
const email = z.string().trim().max(254).email();

export const CHANNEL_CONFIG = {
  email: z.object({
    host,
    port: port.default(587),
    /** true＝一連線就 TLS（465）；false＝STARTTLS（587）或明文（25）。 */
    secure: z.boolean().default(false),
    user: z.string().trim().max(254).optional(),
    pass: z.string().max(500).optional(),
    from: email,
    to: z.array(email).min(1).max(20),
  }),
  slack: z.object({ url: httpsUrl }),
  discord: z.object({ url: httpsUrl }),
  teams: z.object({ url: httpsUrl }),
  webhook: z.object({ url: httpUrl, hmacSecret: z.string().max(500).optional() }),
  syslog: z.object({
    host,
    port: port.default(514),
    protocol: z.enum(['udp', 'tcp']).default('udp'),
    format: z.enum(['rfc5424', 'cef']).default('rfc5424'),
  }),
} satisfies Record<ChannelKind, z.ZodType>;

export interface NotifyMessage {
  event: string;
  title: string;
  lines: string[];
  link?: string | null;
  /** 最嚴重的項目（syslog／CEF 等級用）。 */
  severity?: string | null;
}

/**
 * 驗證並加密設定。更新時沒填的祕密欄位沿用舊值（`prev` 是加密後的舊設定），所以網頁不用把祕密送回瀏覽器。
 */
export function prepareConfig(kind: ChannelKind, input: Record<string, unknown>, key: Buffer, prev?: Record<string, unknown>): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...input };
  for (const f of SECRET_FIELDS[kind]) {
    if ((merged[f] === undefined || merged[f] === '') && prev && typeof prev[f] === 'string') merged[f] = decrypt(key, prev[f] as string);
  }
  const parsed = CHANNEL_CONFIG[kind].parse(merged) as Record<string, unknown>;
  for (const f of SECRET_FIELDS[kind]) {
    const v = parsed[f];
    if (typeof v === 'string' && v) parsed[f] = encrypt(key, v);
    else delete parsed[f];
  }
  return parsed;
}

export function decryptConfig(kind: ChannelKind, config: Record<string, unknown>, key: Buffer): Record<string, unknown> {
  const out = { ...config };
  for (const f of SECRET_FIELDS[kind]) if (isEncrypted(out[f])) out[f] = decrypt(key, out[f] as string);
  return out;
}

/** 給網頁看的設定：祕密只說「已設定」，webhook 網址只露主機名。 */
export function maskConfig(kind: ChannelKind, config: Record<string, unknown>, key: Buffer): Record<string, unknown> {
  const out: Record<string, unknown> = { ...config };
  for (const f of SECRET_FIELDS[kind]) {
    if (out[f] === undefined) continue;
    if (f === 'url') {
      try {
        out[f] = `${new URL(decrypt(key, String(out[f]))).origin}/…`;
      } catch {
        out[f] = '••••';
      }
    } else out[f] = '••••';
  }
  return out;
}

/** 一句話描述頻道送到哪（列表用）。 */
export function targetOf(kind: ChannelKind, masked: Record<string, unknown>): string {
  if (kind === 'email') return (masked.to as string[] | undefined)?.join(', ') ?? '';
  if (kind === 'syslog') return `${masked.protocol}://${masked.host}:${masked.port} (${masked.format})`;
  return String(masked.url ?? '');
}

// ---- 送出 ----

export interface SendDeps {
  fetch?: typeof fetch;
  /** 測試用：換掉 nodemailer 的 transport。 */
  smtpTransport?: (config: Record<string, unknown>) => { sendMail: (m: Record<string, unknown>) => Promise<unknown> };
  hostname?: string;
  version?: string;
}

const TIMEOUT_MS = 10_000;

function plainText(m: NotifyMessage, linkLabel: string): string {
  return [m.title, '', ...m.lines, ...(m.link ? ['', `${linkLabel}: ${m.link}`] : [])].join('\n');
}

async function post(f: typeof fetch, url: string, body: string, headers: Record<string, string> = {}): Promise<void> {
  const res = await f(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'ai-security-monitor-hub', ...headers },
    body,
    signal: AbortSignal.timeout(TIMEOUT_MS),
    redirect: 'error',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

const SYSLOG_SEV: Record<string, number> = { critical: 2, high: 3, medium: 4, low: 5, info: 6 };
const CEF_SEV: Record<string, number> = { critical: 10, high: 8, medium: 5, low: 3, info: 1 };

const cefHeader = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
const cefValue = (s: string) => s.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r?\n/g, '\\n');

/** RFC 5424（facility local0）或 CEF 一行。 */
export function syslogLine(m: NotifyMessage, format: 'rfc5424' | 'cef', hostname: string, version: string, now = new Date()): string {
  const sev = SYSLOG_SEV[m.severity ?? 'info'] ?? 6;
  const pri = 16 * 8 + sev;
  const msg =
    format === 'cef'
      ? `CEF:0|ai-security-monitor|Security Hub|${cefHeader(version)}|${cefHeader(m.event)}|${cefHeader(m.title)}|${CEF_SEV[m.severity ?? 'info'] ?? 1}|msg=${cefValue(m.lines.join('\n'))}${m.link ? ` request=${cefValue(m.link)}` : ''}`
      : `${m.title} | ${m.lines.join(' | ')}${m.link ? ` | ${m.link}` : ''}`;
  return `<${pri}>1 ${now.toISOString()} ${hostname.replace(/\s+/g, '-') || '-'} ai-security-monitor-hub - ${m.event} - ${msg.replace(/[\r\n]+/g, ' ')}`;
}

function sendSyslog(cfg: Record<string, unknown>, line: string): Promise<void> {
  const h = String(cfg.host);
  const p = Number(cfg.port);
  if (cfg.protocol === 'tcp') {
    return new Promise((resolve, reject) => {
      const s = net.createConnection({ host: h, port: p, timeout: TIMEOUT_MS }, () => s.end(`${line}\n`, () => resolve()));
      s.on('timeout', () => s.destroy(new Error('timeout')));
      s.on('error', reject);
    });
  }
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket(net.isIPv6(h) ? 'udp6' : 'udp4');
    s.send(Buffer.from(line), p, h, (err) => {
      s.close();
      if (err) reject(err);
      else resolve();
    });
  });
}

/** Slack 的 mrkdwn：`<…>` 是連結與 @提及，主機傳來的文字要跳脫。 */
export function slackEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** 送一則訊息；失敗丟例外（呼叫端記錄並重試）。`config` 已解密。 */
export async function sendTo(kind: ChannelKind, config: Record<string, unknown>, m: NotifyMessage, linkLabel: string, deps: SendDeps = {}): Promise<void> {
  const f = deps.fetch ?? fetch;
  switch (kind) {
    case 'slack':
      return post(
        f,
        String(config.url),
        JSON.stringify({ text: `*${slackEscape(m.title)}*\n${m.lines.map(slackEscape).join('\n')}${m.link ? `\n<${m.link}|${slackEscape(linkLabel)}>` : ''}` }),
      );
    case 'discord': {
      const text = `**${m.title}**\n${m.lines.join('\n')}${m.link ? `\n${m.link}` : ''}`;
      // allowed_mentions 空的：主機名稱寫成 @everyone 也不會真的通知整個頻道
      return post(f, String(config.url), JSON.stringify({ username: 'ai-security-monitor', content: text.slice(0, 1990), allowed_mentions: { parse: [] } }));
    }
    case 'teams':
      return post(
        f,
        String(config.url),
        JSON.stringify({
          type: 'message',
          attachments: [
            {
              contentType: 'application/vnd.microsoft.card.adaptive',
              content: {
                type: 'AdaptiveCard',
                version: '1.4',
                $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
                body: [
                  { type: 'TextBlock', text: m.title, weight: 'Bolder', wrap: true },
                  { type: 'TextBlock', text: m.lines.join('\n\n'), wrap: true },
                ],
                actions: m.link ? [{ type: 'Action.OpenUrl', title: linkLabel, url: m.link }] : [],
              },
            },
          ],
        }),
      );
    case 'webhook': {
      const body = JSON.stringify({ event: m.event, title: m.title, lines: m.lines, severity: m.severity ?? null, link: m.link ?? null, sent_at: new Date().toISOString() });
      const headers: Record<string, string> = {};
      if (typeof config.hmacSecret === 'string' && config.hmacSecret) {
        const ts = String(Math.floor(Date.now() / 1000));
        headers['x-aism-timestamp'] = ts;
        headers['x-aism-signature'] = `sha256=${createHmac('sha256', config.hmacSecret).update(`${ts}.${body}`).digest('hex')}`;
      }
      return post(f, String(config.url), body, headers);
    }
    case 'syslog':
      return sendSyslog(config, syslogLine(m, config.format === 'cef' ? 'cef' : 'rfc5424', deps.hostname ?? os.hostname(), deps.version ?? '0'));
    case 'email': {
      const transportCfg = {
        host: config.host,
        port: config.port,
        secure: config.secure === true,
        auth: config.user ? { user: config.user, pass: config.pass ?? '' } : undefined,
        connectionTimeout: TIMEOUT_MS,
        greetingTimeout: TIMEOUT_MS,
        socketTimeout: TIMEOUT_MS,
      };
      const transport = deps.smtpTransport ? deps.smtpTransport(transportCfg) : nodemailer.createTransport(transportCfg as Parameters<typeof nodemailer.createTransport>[0]);
      await transport.sendMail({
        from: String(config.from),
        to: (config.to as string[]).join(', '),
        subject: m.title.slice(0, 200),
        text: plainText(m, linkLabel),
      });
      return;
    }
  }
}
