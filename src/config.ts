import type { RateLimitRule } from './types.ts';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export interface MagicLinkConfig {
  /** HMAC key for token, code and session hashes. At least 32 characters. */
  secret: string;
  /** Public origin of the app, e.g. https://kaiju.example. Used to build the link. */
  baseUrl: string;
  /** Path that consumes the link. Default /auth/verify. */
  verifyPath: string;
  /** Link and code lifetime. Plan §4.2: 15 minutes. */
  linkTtlMs: number;
  /** Wrong 6-digit codes tolerated per link before it is burned. */
  maxCodeAttempts: number;
  /** Session lifetime. Plan §4.2: 30 days. */
  sessionTtlMs: number;
  /** Cookie name for the session token. */
  cookieName: string;
  /** Cookie Secure flag. Only false for http://localhost development. */
  cookieSecure: boolean;
  /** Where a first-time user lands after login. */
  onboardingPath: string;
  /** Where a returning user lands when no safe `next` was given. */
  defaultNextPath: string;
  /** "From" header for outgoing mail, e.g. 开局 <login@kaiju.example>. */
  emailFrom: string;
  /** Product name shown in email copy. */
  appName: string;
  rateLimits: {
    /** Per email address, short window. Plan gives 3 per 10 minutes for SMS; same here. */
    perEmail: RateLimitRule;
    /** Per email address, daily cap. */
    perEmailDaily: RateLimitRule;
    /** Per client IP for link requests. */
    perIp: RateLimitRule;
    /** Per client IP for verification attempts (links and codes together). */
    verifyPerIp: RateLimitRule;
  };
}

export type MagicLinkConfigInput = Partial<MagicLinkConfig> & Pick<MagicLinkConfig, 'secret' | 'baseUrl' | 'emailFrom'>;

export const DEFAULT_RATE_LIMITS: MagicLinkConfig['rateLimits'] = {
  perEmail: { max: 3, windowMs: 10 * MINUTE },
  perEmailDaily: { max: 10, windowMs: DAY },
  perIp: { max: 10, windowMs: 10 * MINUTE },
  verifyPerIp: { max: 30, windowMs: 10 * MINUTE },
};

export function resolveConfig(input: MagicLinkConfigInput): MagicLinkConfig {
  if (typeof input.secret !== 'string' || input.secret.length < 32) {
    throw new Error('magic-link: secret must be a string of at least 32 characters');
  }
  let baseUrl: URL;
  try {
    baseUrl = new URL(input.baseUrl);
  } catch {
    throw new Error('magic-link: baseUrl must be an absolute URL');
  }
  const isLocalhost = baseUrl.hostname === 'localhost' || baseUrl.hostname === '127.0.0.1';
  if (baseUrl.protocol !== 'https:' && !isLocalhost) {
    throw new Error('magic-link: baseUrl must use https (http is only allowed for localhost)');
  }
  const cookieSecure = input.cookieSecure ?? baseUrl.protocol === 'https:';
  if (!cookieSecure && !isLocalhost) {
    throw new Error('magic-link: cookieSecure=false is only allowed for localhost');
  }
  return {
    secret: input.secret,
    baseUrl: baseUrl.origin,
    verifyPath: input.verifyPath ?? '/auth/verify',
    linkTtlMs: input.linkTtlMs ?? 15 * MINUTE,
    maxCodeAttempts: input.maxCodeAttempts ?? 5,
    sessionTtlMs: input.sessionTtlMs ?? 30 * DAY,
    cookieName: input.cookieName ?? 'kaiju_session',
    cookieSecure,
    onboardingPath: input.onboardingPath ?? '/onboarding',
    defaultNextPath: input.defaultNextPath ?? '/',
    emailFrom: input.emailFrom,
    appName: input.appName ?? '开局',
    rateLimits: { ...DEFAULT_RATE_LIMITS, ...(input.rateLimits ?? {}) },
  };
}

/** Build a config from environment variables (see .env.example). */
export function configFromEnv(env: Record<string, string | undefined> = process.env): MagicLinkConfig {
  const required = (name: string): string => {
    const v = env[name];
    if (!v) throw new Error(`magic-link: missing environment variable ${name}`);
    return v;
  };
  const input: MagicLinkConfigInput = {
    secret: required('MAGIC_LINK_SECRET'),
    baseUrl: required('APP_BASE_URL'),
    emailFrom: required('EMAIL_FROM'),
  };
  if (env.SESSION_COOKIE_NAME) input.cookieName = env.SESSION_COOKIE_NAME;
  if (env.APP_NAME) input.appName = env.APP_NAME;
  return resolveConfig(input);
}
