import type { EmailMessage, Mailer } from '../types.ts';

/** Prints the email to stdout. For local development and demos. */
export class ConsoleMailer implements Mailer {
  private readonly out: (line: string) => void;

  constructor(out: (line: string) => void = (l) => console.log(l)) {
    this.out = out;
  }

  async send(message: EmailMessage): Promise<void> {
    this.out('');
    this.out('──────── magic-link email (not sent) ────────');
    this.out(`From:    ${message.from}`);
    this.out(`To:      ${message.to}`);
    this.out(`Subject: ${message.subject}`);
    this.out('');
    this.out(message.text);
    this.out('──────────────────────────────────────────────');
    this.out('');
  }
}

/** Keeps every message in memory so tests can read the link and code back. */
export class CaptureMailer implements Mailer {
  readonly sent: EmailMessage[] = [];

  async send(message: EmailMessage): Promise<void> {
    this.sent.push(message);
  }

  last(): EmailMessage {
    const m = this.sent[this.sent.length - 1];
    if (!m) throw new Error('no email sent');
    return m;
  }
}
