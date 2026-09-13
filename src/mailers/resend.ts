import type { EmailMessage, Mailer } from '../types.ts';

export interface ResendMailerOptions {
  apiKey: string;
  /** Override for tests. */
  fetch?: typeof fetch;
  endpoint?: string;
}

/**
 * Resend over its REST API (plan §5.2). Kept dependency-free on purpose: the
 * SDK adds nothing we need for one endpoint. Send from a domain with
 * SPF / DKIM / DMARC set up, otherwise login mail lands in spam (§6.4).
 */
export class ResendMailer implements Mailer {
  private readonly opts: ResendMailerOptions;
  private readonly fetchFn: typeof fetch;
  private readonly endpoint: string;

  constructor(opts: ResendMailerOptions) {
    this.opts = opts;
    if (!opts.apiKey) throw new Error('ResendMailer: apiKey is required');
    this.fetchFn = opts.fetch ?? fetch;
    this.endpoint = opts.endpoint ?? 'https://api.resend.com/emails';
  }

  async send(message: EmailMessage): Promise<void> {
    const res = await this.fetchFn(this.endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.opts.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: message.from,
        to: [message.to],
        subject: message.subject,
        html: message.html,
        text: message.text,
        // Login mail is transactional: no tracking, no list-unsubscribe.
        headers: { 'X-Entity-Ref-ID': crypto.randomUUID() },
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`ResendMailer: ${res.status} ${res.statusText} ${body}`.trim());
    }
  }
}
