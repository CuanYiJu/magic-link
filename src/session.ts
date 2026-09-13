import type { Clock, SessionRecord, SessionStore } from './types.ts';
import type { MagicLinkConfig } from './config.ts';
import { hmac, newId, randomToken } from './crypto.ts';

export interface SessionCookieOptions {
  name: string;
  secure: boolean;
  /** Seconds. */
  maxAge: number;
}

/**
 * Plan §4.2: 30 days, HttpOnly + Secure + SameSite=Lax. Path=/ so every
 * route sees it. No Domain attribute so it stays host-only.
 */
export function serializeSessionCookie(token: string, opts: SessionCookieOptions): string {
  const parts = [
    `${opts.name}=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${opts.maxAge}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

export function serializeClearedCookie(name: string, secure: boolean): string {
  return serializeSessionCookie('', { name, secure, maxAge: 0 });
}

export function readCookie(cookieHeader: string | null | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

export interface ActiveSession {
  session: SessionRecord;
  userId: string;
}

export class SessionService {
  private readonly store: SessionStore;
  private readonly config: MagicLinkConfig;
  private readonly clock: Clock;

  constructor(store: SessionStore, config: MagicLinkConfig, clock: Clock) {
    this.store = store;
    this.config = config;
    this.clock = clock;
  }

  /** Issue a brand-new session token for the user. Returns the raw token to put in the cookie. */
  async create(userId: string, ctx: { ip?: string | null; userAgent?: string | null } = {}): Promise<{ token: string; session: SessionRecord }> {
    const now = this.clock.now();
    const token = randomToken();
    const session: SessionRecord = {
      id: newId(),
      userId,
      tokenHash: hmac(this.config.secret, 'session', token),
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.config.sessionTtlMs),
      lastSeenAt: now,
      revokedAt: null,
      ip: ctx.ip ?? null,
      userAgent: ctx.userAgent ?? null,
    };
    await this.store.create(session);
    return { token, session };
  }

  /** Resolve a cookie token to a live session, or null. Updates lastSeenAt at most once a minute. */
  async resolve(token: string | null | undefined): Promise<ActiveSession | null> {
    if (!token) return null;
    const session = await this.store.findByTokenHash(hmac(this.config.secret, 'session', token));
    if (!session || session.revokedAt) return null;
    const now = this.clock.now();
    if (session.expiresAt <= now) return null;
    if (now.getTime() - session.lastSeenAt.getTime() > 60_000) {
      await this.store.touch(session.id, now);
    }
    return { session, userId: session.userId };
  }

  async revokeToken(token: string | null | undefined): Promise<void> {
    if (!token) return;
    const session = await this.store.findByTokenHash(hmac(this.config.secret, 'session', token));
    if (session && !session.revokedAt) await this.store.revoke(session.id, this.clock.now());
  }

  /** Log the user out everywhere (account deletion, ban, "sign out all devices"). */
  async revokeAllForUser(userId: string): Promise<number> {
    return this.store.revokeAllForUser(userId, this.clock.now());
  }

  cookie(token: string): string {
    return serializeSessionCookie(token, {
      name: this.config.cookieName,
      secure: this.config.cookieSecure,
      maxAge: Math.floor(this.config.sessionTtlMs / 1000),
    });
  }

  clearedCookie(): string {
    return serializeClearedCookie(this.config.cookieName, this.config.cookieSecure);
  }
}
