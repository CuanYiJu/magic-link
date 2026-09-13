export { MagicLinkService, safeRelativePath } from './service.ts';
export type {
  LoginResult,
  LoginSuccess,
  MagicLinkDeps,
  RequestContext,
  RequestLinkInput,
  RequestLinkResult,
  VerifyFailure,
} from './service.ts';
export { SessionService, readCookie, serializeClearedCookie, serializeSessionCookie } from './session.ts';
export { configFromEnv, resolveConfig, DEFAULT_RATE_LIMITS } from './config.ts';
export type { MagicLinkConfig, MagicLinkConfigInput } from './config.ts';
export { createHandlers } from './http.ts';
export type { HttpOptions, MagicLinkHandlers } from './http.ts';
export { MemoryRateLimiter, unlimited } from './rate-limit.ts';
export { MemorySessionStore, MemoryTokenStore, MemoryUserStore } from './stores/memory.ts';
export { PgSessionStore, PgTokenStore, PgUserStore } from './stores/postgres.ts';
export type { SqlClient } from './stores/postgres.ts';
export { CaptureMailer, ConsoleMailer } from './mailers/console.ts';
export { ResendMailer } from './mailers/resend.ts';
export { SmtpMailer } from './mailers/smtp.ts';
export type { SmtpMailerOptions } from './mailers/smtp.ts';
export { renderLoginEmail } from './email-template.ts';
export type {
  Clock,
  EmailMessage,
  Mailer,
  RateLimiter,
  RateLimitResult,
  RateLimitRule,
  SessionRecord,
  SessionStore,
  TokenRecord,
  TokenStore,
  UserRef,
  UserStore,
} from './types.ts';
