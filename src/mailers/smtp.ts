import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import type { EmailMessage, Mailer } from '../types.ts';

export interface SmtpMailerOptions {
  host: string;
  /** 465 for implicit TLS, 587 for STARTTLS, 25 for a relay on the same network. */
  port: number;
  /** true = implicit TLS (port 465). false = plain connection upgraded with STARTTLS when the server offers it. */
  secure?: boolean;
  /** Omit both when the relay authenticates by network/IP instead of a login. */
  user?: string;
  pass?: string;
  /** Set to false only for a self-signed certificate on a server you control. */
  rejectUnauthorized?: boolean;
  /** Override for tests. */
  transport?: Pick<Transporter, 'sendMail'>;
}

/**
 * Any SMTP server: a self-hosted Postfix / Mailcow / Stalwart, or the SMTP
 * endpoint of a hosted provider (Resend, Postmark, SES, Mailgun all expose one).
 * Deliverability is the server's job, not this class's: whoever runs it must
 * have SPF, DKIM, DMARC and reverse DNS set for the sending domain.
 */
export class SmtpMailer implements Mailer {
  private readonly transport: Pick<Transporter, 'sendMail'>;

  constructor(opts: SmtpMailerOptions) {
    if (!opts.host) throw new Error('SmtpMailer: host is required');
    this.transport =
      opts.transport ??
      nodemailer.createTransport({
        host: opts.host,
        port: opts.port,
        secure: opts.secure ?? opts.port === 465,
        ...(opts.user ? { auth: { user: opts.user, pass: opts.pass ?? '' } } : {}),
        ...(opts.rejectUnauthorized === false ? { tls: { rejectUnauthorized: false } } : {}),
      });
  }

  async send(message: EmailMessage): Promise<void> {
    await this.transport.sendMail({
      from: message.from,
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html,
    });
  }

  /** Build from SMTP_* environment variables; returns null when SMTP_HOST is unset. */
  static fromEnv(env: Record<string, string | undefined> = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {}): SmtpMailer | null {
    if (!env.SMTP_HOST) return null;
    const port = Number(env.SMTP_PORT ?? 587);
    if (!Number.isInteger(port) || port <= 0) throw new Error('SmtpMailer: SMTP_PORT must be a positive integer');
    const opts: SmtpMailerOptions = { host: env.SMTP_HOST, port };
    if (env.SMTP_SECURE !== undefined) opts.secure = env.SMTP_SECURE === 'true';
    if (env.SMTP_USER) opts.user = env.SMTP_USER;
    if (env.SMTP_PASS) opts.pass = env.SMTP_PASS;
    if (env.SMTP_REJECT_UNAUTHORIZED === 'false') opts.rejectUnauthorized = false;
    return new SmtpMailer(opts);
  }
}
