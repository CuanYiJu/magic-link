import { createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';

/** 256 bits of randomness, base64url so it is safe in a query string. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Six decimal digits, zero-padded, from a CSPRNG (never Math.random). */
export function randomCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0');
}

export function newId(): string {
  return randomUUID();
}

/**
 * Keyed hash for anything we look up by secret value. Using an HMAC instead of
 * a bare SHA-256 means a leaked database is useless without the server secret,
 * which matters most for the 6-digit codes (only a million possibilities).
 */
export function hmac(secret: string, purpose: 'link' | 'code' | 'session', value: string): string {
  return createHmac('sha256', secret).update(purpose).update('\0').update(value).digest('hex');
}

/** Constant-time comparison of two hex digests. */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/** Trim and lower-case. Local-part case sensitivity is theoretical; every real provider ignores it. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Strip everything but digits so "123 456" and "123-456" both verify. */
export function normalizeCode(code: string): string {
  return code.replace(/\D/g, '');
}
