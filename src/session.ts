import type { Clock, SessionRecord, SessionStore } from './types.ts';
import type { MagicLinkConfig } from './config.ts';
import { hmac, newId, randomToken } from './crypto.ts';

export interface SessionCookieOptions {
  name: string;
  secure: boolean;
  /** Seconds. */
  maxAge: number;
  /** Used to compute the Expires attribute. Default: now. */
  now?: Date;
}

/**
 * Plan §4.2: 30 days, HttpOnly + Secure + SameSite=Lax. Path=/ so every
 * route sees it. No Domain attribute so it stays host-only. Both Max-Age
 * and Expires are sent: every current browser honours Max-Age, and
 * Expires covers any webview that only reads the older attribute.
 */
export function serializeSessionCookie(token: string, opts: SessionCookieOptions): string {
  const now = opts.now ?? new Date();
  const expires = new Date(now.getTime() + opts.maxAge * 1000);
  const parts = [
    `${opts.name}=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${opts.maxAge}`,
    `Expires=${expires.toUTCString()}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

export function serializeClearedCookie(name: string, secure: boolean): string {
  return serializeSessionCookie('', { name, secure, maxAge: 0, now: new Date(0) });
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
  /**
   * True when this request extended the session (sliding expiry). The
   * browser's cookie still carries the old Max-Age, so the caller should
   * send `cookie(token)` again in the response. At most once per
   * `sessionRenewAfterMs`, so it is cheap to do unconditionally.
   */
  renewed: boolean;
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
      tokenHash: await hmac(this.config.secret, 'session', token),
      createdAt: now,
      expiresAt: this.expiryFrom(now, now),
      lastSeenAt: now,
      revokedAt: null,
      ip: ctx.ip ?? null,
      userAgent: ctx.userAgent ?? null,
    };
    await this.store.create(session);
    return { token, session };
  }

  /**
   * Resolve a cookie token to a live session, or null. Records activity at
   * most once a minute; with sliding expiry on, extends the session at most
   * once per `sessionRenewAfterMs`, never past `sessionAbsoluteMaxMs`.
   */
  async resolve(token: string | null | undefined): Promise<ActiveSession | null> {
    if (!token) return null;
    const session = await this.store.findByTokenHash(await hmac(this.config.secret, 'session', token));
    if (!session || session.revokedAt) return null;
    const now = this.clock.now();
    if (session.expiresAt <= now) return null;

    let renewed = false;
    if (this.config.sessionSliding) {
      const fresh = this.expiryFrom(now, session.createdAt);
      // Renew only when the stored expiry lags the fresh one by more than the
      // renew interval, i.e. the last renewal was at least that long ago.
      if (fresh.getTime() - session.expiresAt.getTime() >= this.config.sessionRenewAfterMs) {
        session.expiresAt = fresh;
        session.lastSeenAt = now;
        await this.store.touch(session.id, now, fresh);
        renewed = true;
      }
    }
    if (!renewed && now.getTime() - session.lastSeenAt.getTime() > 60_000) {
      session.lastSeenAt = now;
      await this.store.touch(session.id, now);
    }
    return { session, userId: session.userId, renewed };
  }

  async revokeToken(token: string | null | undefined): Promise<void> {
    if (!token) return;
    const session = await this.store.findByTokenHash(await hmac(this.config.secret, 'session', token));
    if (session && !session.revokedAt) await this.store.revoke(session.id, this.clock.now());
  }

  /** Log the user out everywhere (account deletion, ban, "sign out all devices"). */
  async revokeAllForUser(userId: string): Promise<number> {
    return this.store.revokeAllForUser(userId, this.clock.now());
  }

  /** Set-Cookie value for a session token, dated from the service clock. */
  cookie(token: string, expiresAt?: Date): string {
    const now = this.clock.now();
    const until = expiresAt ?? new Date(now.getTime() + this.config.sessionTtlMs);
    return serializeSessionCookie(token, {
      name: this.config.cookieName,
      secure: this.config.cookieSecure,
      maxAge: Math.max(0, Math.floor((until.getTime() - now.getTime()) / 1000)),
      now,
    });
  }

  clearedCookie(): string {
    return serializeClearedCookie(this.config.cookieName, this.config.cookieSecure);
  }

  /** now + ttl, capped at createdAt + absolute max. */
  private expiryFrom(now: Date, createdAt: Date): Date {
    const byTtl = now.getTime() + this.config.sessionTtlMs;
    const byCap = createdAt.getTime() + this.config.sessionAbsoluteMaxMs;
    return new Date(Math.min(byTtl, byCap));
  }
}
