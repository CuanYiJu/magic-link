import type { SessionRecord, SessionStore, TokenRecord, TokenStore, UserRef, UserStore } from '../types.ts';
import { newId } from '../crypto.ts';

/** In-memory stores for tests and the local dev server. Not for production. */
export class MemoryTokenStore implements TokenStore {
  readonly records = new Map<string, TokenRecord>();

  async create(record: TokenRecord): Promise<void> {
    this.records.set(record.id, { ...record });
  }

  async findByTokenHash(tokenHash: string): Promise<TokenRecord | null> {
    for (const r of this.records.values()) if (r.tokenHash === tokenHash) return { ...r };
    return null;
  }

  async findLatestActiveByEmail(email: string): Promise<TokenRecord | null> {
    let latest: TokenRecord | null = null;
    for (const r of this.records.values()) {
      if (r.email !== email || r.consumedAt) continue;
      if (!latest || r.createdAt > latest.createdAt) latest = r;
    }
    return latest ? { ...latest } : null;
  }

  async consume(id: string, at: Date): Promise<boolean> {
    const r = this.records.get(id);
    if (!r || r.consumedAt) return false;
    r.consumedAt = at;
    return true;
  }

  async incrementCodeAttempts(id: string): Promise<number> {
    const r = this.records.get(id);
    if (!r) return 0;
    r.codeAttempts += 1;
    return r.codeAttempts;
  }

  async invalidateAllForEmail(email: string, at: Date): Promise<void> {
    for (const r of this.records.values()) if (r.email === email && !r.consumedAt) r.consumedAt = at;
  }

  async purgeExpired(before: Date): Promise<number> {
    let n = 0;
    for (const [id, r] of this.records) if (r.expiresAt < before) { this.records.delete(id); n++; }
    return n;
  }
}

export class MemorySessionStore implements SessionStore {
  readonly records = new Map<string, SessionRecord>();

  async create(record: SessionRecord): Promise<void> {
    this.records.set(record.id, { ...record });
  }

  async findByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    for (const r of this.records.values()) if (r.tokenHash === tokenHash) return { ...r };
    return null;
  }

  async touch(id: string, lastSeenAt: Date, expiresAt?: Date): Promise<void> {
    const r = this.records.get(id);
    if (!r) return;
    r.lastSeenAt = lastSeenAt;
    if (expiresAt) r.expiresAt = expiresAt;
  }

  async revoke(id: string, at: Date): Promise<void> {
    const r = this.records.get(id);
    if (r && !r.revokedAt) r.revokedAt = at;
  }

  async revokeAllForUser(userId: string, at: Date): Promise<number> {
    let n = 0;
    for (const r of this.records.values()) if (r.userId === userId && !r.revokedAt) { r.revokedAt = at; n++; }
    return n;
  }

  async purgeExpired(before: Date): Promise<number> {
    let n = 0;
    for (const [id, r] of this.records) if (r.expiresAt < before) { this.records.delete(id); n++; }
    return n;
  }
}

export interface MemoryUser {
  id: string;
  email: string;
  createdAt: Date;
  lastLoginAt: Date | null;
  banned: boolean;
}

export class MemoryUserStore implements UserStore {
  readonly users = new Map<string, MemoryUser>();

  async findOrCreateByEmail(email: string, at: Date): Promise<UserRef> {
    for (const u of this.users.values()) if (u.email === email) return { id: u.id, email, isNew: false };
    const user: MemoryUser = { id: newId(), email, createdAt: at, lastLoginAt: null, banned: false };
    this.users.set(user.id, user);
    return { id: user.id, email, isNew: true };
  }

  async recordLogin(userId: string, at: Date): Promise<void> {
    const u = this.users.get(userId);
    if (u) u.lastLoginAt = at;
  }

  async canLogin(userId: string): Promise<boolean> {
    return !(this.users.get(userId)?.banned ?? false);
  }
}
