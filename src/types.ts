/**
 * Contracts the magic link service depends on. Everything that touches the
 * outside world (database, email, clock, rate limiting) is behind one of these
 * interfaces so the core logic can be tested without infrastructure and
 * dropped into the Next.js app with real adapters later.
 */

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

/** A pending login: one row per magic link email sent. */
export interface TokenRecord {
  id: string;
  /** Normalised (trimmed, lower-cased) email address. */
  email: string;
  /** HMAC of the opaque link token. The raw token is never stored. */
  tokenHash: string;
  /** HMAC of the 6-digit code. The raw code is never stored. */
  codeHash: string;
  createdAt: Date;
  expiresAt: Date;
  /** Set when the link or the code has been used, or when it was invalidated. */
  consumedAt: Date | null;
  /** Number of wrong 6-digit codes tried against this record. */
  codeAttempts: number;
  requestIp: string | null;
  requestUserAgent: string | null;
}

export interface TokenStore {
  create(record: TokenRecord): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<TokenRecord | null>;
  /** Newest record for the email that has not been consumed yet (may be expired). */
  findLatestActiveByEmail(email: string): Promise<TokenRecord | null>;
  /**
   * Atomically mark a record consumed. Returns false if it was already
   * consumed, which is what makes the link single-use under concurrency.
   */
  consume(id: string, at: Date): Promise<boolean>;
  /** Increment the wrong-code counter and return the new value. */
  incrementCodeAttempts(id: string): Promise<number>;
  /** Mark every unconsumed record for the email as consumed. */
  invalidateAllForEmail(email: string, at: Date): Promise<void>;
  /** Housekeeping: delete records whose expiry is before the given time. */
  purgeExpired(before: Date): Promise<number>;
}

export interface SessionRecord {
  id: string;
  userId: string;
  /** HMAC of the opaque session token stored in the cookie. */
  tokenHash: string;
  createdAt: Date;
  expiresAt: Date;
  lastSeenAt: Date;
  revokedAt: Date | null;
  ip: string | null;
  userAgent: string | null;
}

export interface SessionStore {
  create(record: SessionRecord): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<SessionRecord | null>;
  /** Record activity; `expiresAt` is passed when the session is being extended (sliding expiry). */
  touch(id: string, lastSeenAt: Date, expiresAt?: Date): Promise<void>;
  revoke(id: string, at: Date): Promise<void>;
  revokeAllForUser(userId: string, at: Date): Promise<number>;
  purgeExpired(before: Date): Promise<number>;
}

export interface UserRef {
  id: string;
  email: string;
  /** True when this login created the account (drives the onboarding redirect). */
  isNew: boolean;
}

/**
 * The users table belongs to the application, not to this service. The
 * service only needs to resolve an email to a user id and record the login.
 */
export interface UserStore {
  findOrCreateByEmail(email: string, at: Date): Promise<UserRef>;
  recordLogin(userId: string, at: Date): Promise<void>;
  /** Return false to refuse login (e.g. status = banned). Default: allow. */
  canLogin?(userId: string): Promise<boolean>;
}

export interface EmailMessage {
  to: string;
  from: string;
  subject: string;
  html: string;
  text: string;
}

export interface Mailer {
  send(message: EmailMessage): Promise<void>;
}

export interface RateLimitRule {
  max: number;
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  /** Milliseconds until the caller may try again; 0 when allowed. */
  retryAfterMs: number;
}

export interface RateLimiter {
  /** Count one attempt against the key and report whether it is allowed. */
  hit(key: string, rule: RateLimitRule): Promise<RateLimitResult>;
}
