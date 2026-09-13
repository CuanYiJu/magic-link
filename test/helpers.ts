import type { Clock } from '../src/types.ts';
import { MagicLinkService } from '../src/service.ts';
import { resolveConfig, type MagicLinkConfigInput } from '../src/config.ts';
import { MemoryRateLimiter } from '../src/rate-limit.ts';
import { MemorySessionStore, MemoryTokenStore, MemoryUserStore } from '../src/stores/memory.ts';
import { CaptureMailer } from '../src/mailers/console.ts';

export class FakeClock implements Clock {
  private t: number;

  constructor(t: number = Date.parse('2026-09-12T12:00:00Z')) {
    this.t = t;
  }
  now(): Date {
    return new Date(this.t);
  }
  advance(ms: number): void {
    this.t += ms;
  }
}

export const SECRET = 'test-secret-test-secret-test-secret-0123456789';

export function makeService(overrides: Partial<MagicLinkConfigInput> = {}) {
  const clock = new FakeClock();
  const tokens = new MemoryTokenStore();
  const sessions = new MemorySessionStore();
  const users = new MemoryUserStore();
  const mailer = new CaptureMailer();
  const rateLimiter = new MemoryRateLimiter(clock);
  const config = resolveConfig({
    secret: SECRET,
    baseUrl: 'https://kaiju.test',
    emailFrom: '开局 <login@kaiju.test>',
    ...overrides,
  });
  const service = new MagicLinkService({ config, tokens, sessions, users, mailer, rateLimiter, clock });
  return { service, clock, tokens, sessions, users, mailer, config };
}

/** Pull the link token and the 6-digit code out of the last captured email. */
export function credentialsFrom(mailer: CaptureMailer): { token: string; code: string; link: string } {
  const text = mailer.last().text;
  const link = /https?:\/\/\S+/.exec(text)?.[0];
  if (!link) throw new Error('no link in email');
  const token = new URL(link).searchParams.get('token');
  const code = /6 位码即可：(\d{6})/.exec(text)?.[1];
  if (!token || !code) throw new Error('could not parse credentials from email');
  return { token, code, link };
}
