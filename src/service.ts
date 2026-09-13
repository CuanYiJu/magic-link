import { z } from 'zod';
import type { Clock, Mailer, RateLimiter, SessionRecord, SessionStore, TokenRecord, TokenStore, UserRef, UserStore } from './types.ts';
import { systemClock } from './types.ts';
import type { MagicLinkConfig } from './config.ts';
import { hmac, newId, normalizeCode, normalizeEmail, randomCode, randomToken, safeEqualHex } from './crypto.ts';
import { renderLoginEmail } from './email-template.ts';
import { SessionService } from './session.ts';

export interface RequestContext {
  ip?: string | null;
  userAgent?: string | null;
  /**
   * Session token already presented by the client (from the cookie). It is
   * revoked on successful login so a session set before authentication can
   * never carry over into the authenticated one (session fixation, §5.6).
   */
  existingSessionToken?: string | null;
}

export interface RequestLinkInput extends RequestContext {
  email: string;
}

export type RequestLinkResult =
  /** Email accepted. Sent whether or not the address is known, to avoid account enumeration. */
  | { status: 'sent'; email: string }
  | { status: 'invalid_email' }
  | { status: 'rate_limited'; retryAfterMs: number }
  /** The mail provider rejected or failed the send (quota, outage, bad config). Nothing is pending. */
  | { status: 'send_failed'; reason: string };

export interface Logger {
  error(message: string, meta?: Record<string, unknown>): void;
}

export interface LoginSuccess {
  status: 'ok';
  user: UserRef;
  /** Raw session token. Put it in the cookie; it is not stored anywhere. */
  sessionToken: string;
  session: SessionRecord;
  /** Set-Cookie header value for the new session. */
  cookie: string;
}

export type VerifyFailure =
  | { status: 'invalid' }        // unknown token, malformed input, or wrong code
  | { status: 'expired' }
  | { status: 'used' }           // link already consumed (or superseded by a newer request)
  | { status: 'too_many_attempts' }
  | { status: 'rate_limited'; retryAfterMs: number }
  | { status: 'forbidden' };     // user exists but may not log in (banned)

export type LoginResult = LoginSuccess | VerifyFailure;

export interface MagicLinkDeps {
  config: MagicLinkConfig;
  tokens: TokenStore;
  sessions: SessionStore;
  users: UserStore;
  mailer: Mailer;
  rateLimiter: RateLimiter;
  clock?: Clock;
  /** Receives mailer failures so an operator notices a quota or outage. Default: console.error. */
  logger?: Logger;
}

const emailSchema = z.string().trim().min(3).max(254).email();
const tokenSchema = z.string().min(32).max(128).regex(/^[A-Za-z0-9_-]+$/);

/**
 * Passwordless login for 开局 (plan §4.2, §5.6).
 *
 * One email carries two equivalent credentials for the same pending login:
 *  - a link, for users reading mail in a normal browser;
 *  - a 6-digit code, for users who opened the app inside WeChat and cannot
 *    follow a link back into that webview.
 * Whichever is used first consumes the record; the other stops working.
 */
export class MagicLinkService {
  readonly sessions: SessionService;
  private readonly deps: MagicLinkDeps;
  private readonly clock: Clock;

  constructor(deps: MagicLinkDeps) {
    this.deps = deps;
    this.clock = deps.clock ?? systemClock;
    this.sessions = new SessionService(deps.sessions, deps.config, this.clock);
  }

  get config(): MagicLinkConfig {
    return this.deps.config;
  }

  /** Step 1: user submits an email address. */
  async requestLink(input: RequestLinkInput): Promise<RequestLinkResult> {
    const parsed = emailSchema.safeParse(input.email);
    if (!parsed.success) return { status: 'invalid_email' };
    const email = normalizeEmail(parsed.data);
    const { rateLimits } = this.deps.config;

    // IP first so a single client cannot burn many addresses' quotas.
    const checks = [
      input.ip ? this.deps.rateLimiter.hit(`ml:req:ip:${input.ip}`, rateLimits.perIp) : null,
      this.deps.rateLimiter.hit(`ml:req:email:${email}`, rateLimits.perEmail),
      this.deps.rateLimiter.hit(`ml:req:email:day:${email}`, rateLimits.perEmailDaily),
    ];
    let retryAfterMs = 0;
    for (const check of checks) {
      const r = await check;
      if (r && !r.allowed) retryAfterMs = Math.max(retryAfterMs, r.retryAfterMs);
    }
    if (retryAfterMs > 0) return { status: 'rate_limited', retryAfterMs };

    const now = this.clock.now();
    const token = randomToken();
    const code = randomCode();
    const record: TokenRecord = {
      id: newId(),
      email,
      tokenHash: hmac(this.deps.config.secret, 'link', token),
      codeHash: hmac(this.deps.config.secret, 'code', code),
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.deps.config.linkTtlMs),
      consumedAt: null,
      codeAttempts: 0,
      requestIp: input.ip ?? null,
      requestUserAgent: input.userAgent ?? null,
    };

    // Only the newest email is valid. This keeps "which code do I type" simple
    // and stops an attacker from keeping an old, unknowingly-leaked link alive.
    await this.deps.tokens.invalidateAllForEmail(email, now);
    await this.deps.tokens.create(record);

    const message = renderLoginEmail({
      to: email,
      from: this.deps.config.emailFrom,
      appName: this.deps.config.appName,
      link: this.buildLink(token),
      code,
      ttlMinutes: Math.round(this.deps.config.linkTtlMs / 60_000),
    });
    try {
      await this.deps.mailer.send(message);
    } catch (err) {
      // No email reached the user, so nothing must stay pending: burn the record
      // and let the caller tell the user to try again later.
      await this.deps.tokens.consume(record.id, this.clock.now());
      const reason = err instanceof Error ? err.message : String(err);
      (this.deps.logger ?? console).error('magic-link: login email failed to send', { email, reason });
      return { status: 'send_failed', reason };
    }
    return { status: 'sent', email };
  }

  /** Step 2a: user opened the link from the email. */
  async verifyLink(token: string, ctx: RequestContext = {}): Promise<LoginResult> {
    const limited = await this.verifyRateLimit(ctx);
    if (limited) return limited;
    const parsed = tokenSchema.safeParse(token);
    if (!parsed.success) return { status: 'invalid' };

    const record = await this.deps.tokens.findByTokenHash(hmac(this.deps.config.secret, 'link', parsed.data));
    if (!record) return { status: 'invalid' };
    if (record.consumedAt) return { status: 'used' };
    if (record.expiresAt <= this.clock.now()) return { status: 'expired' };
    return this.completeLogin(record, ctx);
  }

  /** Step 2b: user typed the 6-digit code from the email (WeChat path). */
  async verifyCode(email: string, code: string, ctx: RequestContext = {}): Promise<LoginResult> {
    const limited = await this.verifyRateLimit(ctx);
    if (limited) return limited;
    const parsedEmail = emailSchema.safeParse(email);
    if (!parsedEmail.success) return { status: 'invalid' };
    const digits = normalizeCode(code);
    if (digits.length !== 6) return { status: 'invalid' };

    const record = await this.deps.tokens.findLatestActiveByEmail(normalizeEmail(parsedEmail.data));
    if (!record) return { status: 'invalid' };
    if (record.expiresAt <= this.clock.now()) return { status: 'expired' };
    if (record.codeAttempts >= this.deps.config.maxCodeAttempts) return { status: 'too_many_attempts' };

    if (!safeEqualHex(record.codeHash, hmac(this.deps.config.secret, 'code', digits))) {
      const attempts = await this.deps.tokens.incrementCodeAttempts(record.id);
      if (attempts >= this.deps.config.maxCodeAttempts) {
        // Burn the record so the link in the same email cannot be brute-forced either.
        await this.deps.tokens.consume(record.id, this.clock.now());
        return { status: 'too_many_attempts' };
      }
      return { status: 'invalid' };
    }
    return this.completeLogin(record, ctx);
  }

  /**
   * Resolve a cookie token to the logged-in user, or null. When the session
   * was just extended (sliding expiry), `setCookie` holds a fresh Set-Cookie
   * value the caller should add to its response so the browser's copy is
   * extended too; it is undefined otherwise.
   */
  async getSession(
    sessionToken: string | null | undefined,
  ): Promise<{ userId: string; session: SessionRecord; setCookie?: string } | null> {
    const active = await this.sessions.resolve(sessionToken);
    if (!active) return null;
    const result: { userId: string; session: SessionRecord; setCookie?: string } = {
      userId: active.userId,
      session: active.session,
    };
    if (active.renewed && sessionToken) result.setCookie = this.sessions.cookie(sessionToken, active.session.expiresAt);
    return result;
  }

  /** Revoke the presented session. Always succeeds; returns the cookie that clears it. */
  async logout(sessionToken: string | null | undefined): Promise<{ cookie: string }> {
    await this.sessions.revokeToken(sessionToken);
    return { cookie: this.sessions.clearedCookie() };
  }

  /** Decide where to send the user after login. Rejects anything that is not a same-origin path. */
  resolveNextPath(next: string | null | undefined, user: UserRef): string {
    if (user.isNew) return this.deps.config.onboardingPath;
    return safeRelativePath(next) ?? this.deps.config.defaultNextPath;
  }

  /** Housekeeping for a cron job: drop expired tokens and sessions. */
  async purgeExpired(): Promise<{ tokens: number; sessions: number }> {
    const now = this.clock.now();
    return {
      tokens: await this.deps.tokens.purgeExpired(now),
      sessions: await this.deps.sessions.purgeExpired(now),
    };
  }

  buildLink(token: string): string {
    const url = new URL(this.deps.config.verifyPath, this.deps.config.baseUrl);
    url.searchParams.set('token', token);
    return url.toString();
  }

  private async verifyRateLimit(ctx: RequestContext): Promise<VerifyFailure | null> {
    if (!ctx.ip) return null;
    const r = await this.deps.rateLimiter.hit(`ml:verify:ip:${ctx.ip}`, this.deps.config.rateLimits.verifyPerIp);
    return r.allowed ? null : { status: 'rate_limited', retryAfterMs: r.retryAfterMs };
  }

  private async completeLogin(record: TokenRecord, ctx: RequestContext): Promise<LoginResult> {
    const now = this.clock.now();
    // Atomic: two simultaneous clicks on the same link log in exactly once.
    const consumed = await this.deps.tokens.consume(record.id, now);
    if (!consumed) return { status: 'used' };

    const user = await this.deps.users.findOrCreateByEmail(record.email, now);
    if (this.deps.users.canLogin && !(await this.deps.users.canLogin(user.id))) {
      return { status: 'forbidden' };
    }

    // Session fixation defence: whatever session the browser already had is
    // dropped and a fresh token is issued after authentication.
    await this.sessions.revokeToken(ctx.existingSessionToken);
    const { token: sessionToken, session } = await this.sessions.create(user.id, ctx);
    await this.deps.users.recordLogin(user.id, now);

    return { status: 'ok', user, sessionToken, session, cookie: this.sessions.cookie(sessionToken, session.expiresAt) };
  }
}

/**
 * Accept only "/path?query#hash" style values: no scheme, no "//host", no
 * backslashes (which some browsers normalise to slashes). Prevents open redirects.
 */
export function safeRelativePath(value: string | null | undefined): string | null {
  if (!value) return null;
  if (value.length > 2048) return null;
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return null;
  if (/[\\\r\n\0]/.test(value)) return null;
  try {
    const u = new URL(value, 'https://placeholder.invalid');
    if (u.origin !== 'https://placeholder.invalid') return null;
  } catch {
    return null;
  }
  return value;
}
