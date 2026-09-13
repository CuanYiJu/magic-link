/**
 * Web Crypto only: no `node:crypto`, no `Buffer`. The same code runs on
 * Node ≥ 20, Cloudflare Workers, Deno and Bun. Hashes are byte-for-byte
 * identical to the earlier node:crypto implementation, so rows already in
 * the database stay valid.
 */

const encoder = new TextEncoder();
const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** 256 bits of randomness, base64url so it is safe in a query string. */
export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64url(buf);
}

/** Six decimal digits, zero-padded, from a CSPRNG with rejection sampling (no modulo bias). */
export function randomCode(): string {
  const buf = new Uint32Array(1);
  const range = 1_000_000;
  const limit = 0x1_0000_0000 - (0x1_0000_0000 % range);
  let x: number;
  do {
    crypto.getRandomValues(buf);
    x = buf[0] as number;
  } while (x >= limit);
  return (x % range).toString().padStart(6, '0');
}

export function newId(): string {
  return crypto.randomUUID();
}

// One imported key per secret; importing is the slow part of HMAC.
// Typed via crypto.subtle so no DOM lib or node: type import is needed.
type HmacKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;
const keyCache = new Map<string, Promise<HmacKey>>();

function keyFor(secret: string): Promise<HmacKey> {
  let key = keyCache.get(secret);
  if (!key) {
    key = crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    keyCache.set(secret, key);
  }
  return key;
}

/**
 * Keyed hash for anything we look up by secret value. Using an HMAC instead of
 * a bare SHA-256 means a leaked database is useless without the server secret,
 * which matters most for the 6-digit codes (only a million possibilities).
 * Input bytes are `purpose || 0x00 || value`, as before.
 */
export async function hmac(secret: string, purpose: 'link' | 'code' | 'session', value: string): Promise<string> {
  const key = await keyFor(secret);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(`${purpose}\0${value}`));
  return hex(new Uint8Array(sig));
}

/** Constant-time comparison of two hex digests (no early exit on the first differing byte). */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Trim and lower-case. Local-part case sensitivity is theoretical; every real provider ignores it. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Strip everything but digits so "123 456" and "123-456" both verify. */
export function normalizeCode(code: string): string {
  return code.replace(/\D/g, '');
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function base64url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out += BASE64URL[n >> 18]! + BASE64URL[(n >> 12) & 63]! + BASE64URL[(n >> 6) & 63]! + BASE64URL[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] as number) << 16;
    out += BASE64URL[n >> 18]! + BASE64URL[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += BASE64URL[n >> 18]! + BASE64URL[(n >> 12) & 63]! + BASE64URL[(n >> 6) & 63]!;
  }
  return out;
}
