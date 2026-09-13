import type { SessionRecord, SessionStore, TokenRecord, TokenStore, UserRef, UserStore } from '../types.ts';
import { newId } from '../crypto.ts';

/**
 * The narrowest slice of a Postgres client we need. `pg.Pool`, `pg.Client`
 * and Drizzle's `db.$client` all satisfy it as-is; for postgres.js wrap
 * `sql.unsafe(text, params)`.
 */
export interface SqlClient {
  query<Row = Record<string, unknown>>(text: string, params?: unknown[]): Promise<{ rows: Row[]; rowCount?: number | null }>;
}

interface TokenRow {
  id: string;
  email: string;
  token_hash: string;
  code_hash: string;
  created_at: Date;
  expires_at: Date;
  consumed_at: Date | null;
  code_attempts: number;
  request_ip: string | null;
  request_user_agent: string | null;
}

function tokenFromRow(r: TokenRow): TokenRecord {
  return {
    id: r.id,
    email: r.email,
    tokenHash: r.token_hash,
    codeHash: r.code_hash,
    createdAt: new Date(r.created_at),
    expiresAt: new Date(r.expires_at),
    consumedAt: r.consumed_at ? new Date(r.consumed_at) : null,
    codeAttempts: r.code_attempts,
    requestIp: r.request_ip,
    requestUserAgent: r.request_user_agent,
  };
}

export class PgTokenStore implements TokenStore {
  private readonly sql: SqlClient;

  constructor(sql: SqlClient) {
    this.sql = sql;
  }

  async create(t: TokenRecord): Promise<void> {
    await this.sql.query(
      `insert into auth_tokens (id, email, token_hash, code_hash, created_at, expires_at, consumed_at, code_attempts, request_ip, request_user_agent)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [t.id, t.email, t.tokenHash, t.codeHash, t.createdAt, t.expiresAt, t.consumedAt, t.codeAttempts, t.requestIp, t.requestUserAgent],
    );
  }

  async findByTokenHash(tokenHash: string): Promise<TokenRecord | null> {
    const { rows } = await this.sql.query<TokenRow>(`select * from auth_tokens where token_hash = $1`, [tokenHash]);
    return rows[0] ? tokenFromRow(rows[0]) : null;
  }

  async findLatestActiveByEmail(email: string): Promise<TokenRecord | null> {
    const { rows } = await this.sql.query<TokenRow>(
      `select * from auth_tokens where email = $1 and consumed_at is null order by created_at desc limit 1`,
      [email],
    );
    return rows[0] ? tokenFromRow(rows[0]) : null;
  }

  async consume(id: string, at: Date): Promise<boolean> {
    const { rows } = await this.sql.query<{ id: string }>(
      `update auth_tokens set consumed_at = $2 where id = $1 and consumed_at is null returning id`,
      [id, at],
    );
    return rows.length === 1;
  }

  async incrementCodeAttempts(id: string): Promise<number> {
    const { rows } = await this.sql.query<{ code_attempts: number }>(
      `update auth_tokens set code_attempts = code_attempts + 1 where id = $1 returning code_attempts`,
      [id],
    );
    return rows[0]?.code_attempts ?? 0;
  }

  async invalidateAllForEmail(email: string, at: Date): Promise<void> {
    await this.sql.query(`update auth_tokens set consumed_at = $2 where email = $1 and consumed_at is null`, [email, at]);
  }

  async purgeExpired(before: Date): Promise<number> {
    const { rows } = await this.sql.query<{ id: string }>(`delete from auth_tokens where expires_at < $1 returning id`, [before]);
    return rows.length;
  }
}

interface SessionRow {
  id: string;
  user_id: string;
  token_hash: string;
  created_at: Date;
  expires_at: Date;
  last_seen_at: Date;
  revoked_at: Date | null;
  ip: string | null;
  user_agent: string | null;
}

function sessionFromRow(r: SessionRow): SessionRecord {
  return {
    id: r.id,
    userId: r.user_id,
    tokenHash: r.token_hash,
    createdAt: new Date(r.created_at),
    expiresAt: new Date(r.expires_at),
    lastSeenAt: new Date(r.last_seen_at),
    revokedAt: r.revoked_at ? new Date(r.revoked_at) : null,
    ip: r.ip,
    userAgent: r.user_agent,
  };
}

export class PgSessionStore implements SessionStore {
  private readonly sql: SqlClient;

  constructor(sql: SqlClient) {
    this.sql = sql;
  }

  async create(s: SessionRecord): Promise<void> {
    await this.sql.query(
      `insert into sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at, revoked_at, ip, user_agent)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [s.id, s.userId, s.tokenHash, s.createdAt, s.expiresAt, s.lastSeenAt, s.revokedAt, s.ip, s.userAgent],
    );
  }

  async findByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    const { rows } = await this.sql.query<SessionRow>(`select * from sessions where token_hash = $1`, [tokenHash]);
    return rows[0] ? sessionFromRow(rows[0]) : null;
  }

  async touch(id: string, lastSeenAt: Date, expiresAt?: Date): Promise<void> {
    if (expiresAt) {
      await this.sql.query(`update sessions set last_seen_at = $2, expires_at = $3 where id = $1`, [id, lastSeenAt, expiresAt]);
    } else {
      await this.sql.query(`update sessions set last_seen_at = $2 where id = $1`, [id, lastSeenAt]);
    }
  }

  async revoke(id: string, at: Date): Promise<void> {
    await this.sql.query(`update sessions set revoked_at = $2 where id = $1 and revoked_at is null`, [id, at]);
  }

  async revokeAllForUser(userId: string, at: Date): Promise<number> {
    const { rows } = await this.sql.query<{ id: string }>(
      `update sessions set revoked_at = $2 where user_id = $1 and revoked_at is null returning id`,
      [userId, at],
    );
    return rows.length;
  }

  async purgeExpired(before: Date): Promise<number> {
    const { rows } = await this.sql.query<{ id: string }>(`delete from sessions where expires_at < $1 returning id`, [before]);
    return rows.length;
  }
}

/**
 * Works against the plan's `users` table. Adjust the column names here if the
 * app's Drizzle schema ends up different; nothing else in the service cares.
 */
export class PgUserStore implements UserStore {
  private readonly sql: SqlClient;

  constructor(sql: SqlClient) {
    this.sql = sql;
  }

  async findOrCreateByEmail(email: string, at: Date): Promise<UserRef> {
    const existing = await this.sql.query<{ id: string }>(`select id from users where email = $1`, [email]);
    if (existing.rows[0]) return { id: existing.rows[0].id, email, isNew: false };
    // Two first logins racing for the same address: the unique index makes the
    // second insert a no-op, so read back whichever row won.
    const inserted = await this.sql.query<{ id: string }>(
      `insert into users (id, email, created_at) values ($1, $2, $3) on conflict (email) do nothing returning id`,
      [newId(), email, at],
    );
    if (inserted.rows[0]) return { id: inserted.rows[0].id, email, isNew: true };
    const again = await this.sql.query<{ id: string }>(`select id from users where email = $1`, [email]);
    if (!again.rows[0]) throw new Error('PgUserStore: failed to create user');
    return { id: again.rows[0].id, email, isNew: false };
  }

  async recordLogin(userId: string, at: Date): Promise<void> {
    await this.sql.query(`update users set last_login_at = $2 where id = $1`, [userId, at]);
  }

  async canLogin(userId: string): Promise<boolean> {
    const { rows } = await this.sql.query<{ status: string | null }>(`select status from users where id = $1`, [userId]);
    return rows[0] ? rows[0].status !== 'banned' : false;
  }
}
