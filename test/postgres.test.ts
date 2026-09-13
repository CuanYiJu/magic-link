import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PgSessionStore, PgTokenStore, PgUserStore, type SqlClient } from '../src/stores/postgres.ts';

/**
 * These tests do not need a database. They check that each store issues the
 * SQL we expect (parameterised, correct predicates for atomicity) against a
 * recording client. Run migrations/0001_magic_link.sql against a real
 * Postgres for the integration check.
 */
class RecordingSql implements SqlClient {
  calls: { text: string; params: unknown[] }[] = [];
  next: unknown[][] = [];

  async query<Row>(text: string, params: unknown[] = []): Promise<{ rows: Row[] }> {
    this.calls.push({ text: text.replace(/\s+/g, ' ').trim(), params });
    return { rows: (this.next.shift() ?? []) as Row[] };
  }
}

test('PgTokenStore.consume only succeeds when consumed_at is still null', async () => {
  const sql = new RecordingSql();
  const store = new PgTokenStore(sql);
  sql.next.push([{ id: 't1' }]);
  assert.equal(await store.consume('t1', new Date(0)), true);
  sql.next.push([]);
  assert.equal(await store.consume('t1', new Date(0)), false);
  assert.match(sql.calls[0]!.text, /where id = \$1 and consumed_at is null returning id/);
  assert.deepEqual(sql.calls[0]!.params, ['t1', new Date(0)]);
});

test('PgTokenStore maps rows to records and back', async () => {
  const sql = new RecordingSql();
  const store = new PgTokenStore(sql);
  const row = {
    id: 't1', email: 'a@b.co', token_hash: 'th', code_hash: 'ch',
    created_at: '2026-09-12T00:00:00Z', expires_at: '2026-09-12T00:15:00Z', consumed_at: null,
    code_attempts: 2, request_ip: '1.1.1.1', request_user_agent: 'ua',
  };
  sql.next.push([row]);
  const rec = await store.findByTokenHash('th');
  assert.ok(rec);
  assert.equal(rec.email, 'a@b.co');
  assert.equal(rec.expiresAt.toISOString(), '2026-09-12T00:15:00.000Z');
  assert.equal(rec.consumedAt, null);
  assert.equal(rec.codeAttempts, 2);

  await store.create(rec);
  const insert = sql.calls[1]!;
  assert.match(insert.text, /^insert into auth_tokens/);
  assert.equal(insert.params.length, 10);
  assert.ok(!insert.text.includes("'"), 'no inlined literals');
});

test('PgTokenStore.findLatestActiveByEmail orders newest first and skips consumed', async () => {
  const sql = new RecordingSql();
  await new PgTokenStore(sql).findLatestActiveByEmail('a@b.co');
  assert.match(sql.calls[0]!.text, /where email = \$1 and consumed_at is null order by created_at desc limit 1/);
});

test('PgSessionStore.revokeAllForUser returns the number of sessions revoked', async () => {
  const sql = new RecordingSql();
  sql.next.push([{ id: 's1' }, { id: 's2' }]);
  assert.equal(await new PgSessionStore(sql).revokeAllForUser('u1', new Date(0)), 2);
  assert.match(sql.calls[0]!.text, /where user_id = \$1 and revoked_at is null returning id/);
});

test('PgUserStore.findOrCreateByEmail creates once and tolerates a racing insert', async () => {
  const sql = new RecordingSql();
  const store = new PgUserStore(sql);
  // Existing user
  sql.next.push([{ id: 'u1' }]);
  assert.deepEqual(await store.findOrCreateByEmail('a@b.co', new Date(0)), { id: 'u1', email: 'a@b.co', isNew: false });
  // New user
  sql.next.push([], [{ id: 'u2' }]);
  assert.deepEqual(await store.findOrCreateByEmail('b@b.co', new Date(0)), { id: 'u2', email: 'b@b.co', isNew: true });
  assert.match(sql.calls[2]!.text, /on conflict \(email\) do nothing returning id/);
  // Lost the race: select → nothing, insert → nothing, select again → row
  sql.next.push([], [], [{ id: 'u3' }]);
  assert.deepEqual(await store.findOrCreateByEmail('c@b.co', new Date(0)), { id: 'u3', email: 'c@b.co', isNew: false });
});

test('PgUserStore.canLogin is false for banned and for missing users', async () => {
  const sql = new RecordingSql();
  const store = new PgUserStore(sql);
  sql.next.push([{ status: 'active' }]);
  assert.equal(await store.canLogin('u1'), true);
  sql.next.push([{ status: 'banned' }]);
  assert.equal(await store.canLogin('u1'), false);
  sql.next.push([]);
  assert.equal(await store.canLogin('u1'), false);
});
