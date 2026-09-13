import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SessionService, readCookie, serializeClearedCookie, serializeSessionCookie } from '../src/session.ts';
import { resolveConfig } from '../src/config.ts';
import { MemorySessionStore } from '../src/stores/memory.ts';
import { FakeClock, SECRET } from './helpers.ts';

const MIN = 60_000;

test('serializeSessionCookie emits the plan §4.2 attributes and encodes the value', () => {
  const c = serializeSessionCookie('a b', { name: 'kaiju_session', secure: true, maxAge: 2592000 });
  assert.equal(c, 'kaiju_session=a%20b; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax; Secure');
  const insecure = serializeSessionCookie('t', { name: 's', secure: false, maxAge: 1 });
  assert.ok(!insecure.includes('Secure'));
  assert.equal(serializeClearedCookie('s', true), 's=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure');
});

test('readCookie finds the named cookie among others and tolerates junk', () => {
  assert.equal(readCookie('a=1; kaiju_session=tok%20en; b=2', 'kaiju_session'), 'tok en');
  assert.equal(readCookie('kaiju_session=x', 'kaiju_session'), 'x');
  assert.equal(readCookie('kaiju_session_other=x', 'kaiju_session'), null);
  assert.equal(readCookie('', 'kaiju_session'), null);
  assert.equal(readCookie(null, 'kaiju_session'), null);
  assert.equal(readCookie('novalue; kaiju_session', 'kaiju_session'), null);
  assert.equal(readCookie('kaiju_session=%E0%A4%A', 'kaiju_session'), null, 'bad percent-encoding is null, not a throw');
});

function makeSessions() {
  const clock = new FakeClock();
  const store = new MemorySessionStore();
  const config = resolveConfig({ secret: SECRET, baseUrl: 'https://kaiju.test', emailFrom: 'x <x@kaiju.test>' });
  return { clock, store, sessions: new SessionService(store, config, clock) };
}

test('SessionService: create → resolve → revoke', async () => {
  const { sessions, store } = makeSessions();
  const { token, session } = await sessions.create('u1', { ip: '1.2.3.4', userAgent: 'ua' });
  assert.equal(store.records.size, 1);
  assert.ok(!JSON.stringify([...store.records.values()]).includes(token), 'raw token is not stored');
  const active = await sessions.resolve(token);
  assert.equal(active?.userId, 'u1');
  assert.equal(active?.session.id, session.id);
  await sessions.revokeToken(token);
  assert.equal(await sessions.resolve(token), null);
  assert.equal(await sessions.resolve('nope'), null);
  assert.equal(await sessions.resolve(null), null);
});

test('SessionService: lastSeenAt is touched at most once a minute', async () => {
  const { sessions, store, clock } = makeSessions();
  const { token, session } = await sessions.create('u1');
  clock.advance(30_000);
  await sessions.resolve(token);
  assert.equal(store.records.get(session.id)?.lastSeenAt.getTime(), session.createdAt.getTime());
  clock.advance(31_000);
  await sessions.resolve(token);
  assert.equal(store.records.get(session.id)?.lastSeenAt.getTime(), clock.now().getTime());
});

test('SessionService: expiry is exactly 30 days from creation', async () => {
  const { sessions, clock } = makeSessions();
  const { token, session } = await sessions.create('u1');
  assert.equal(session.expiresAt.getTime() - session.createdAt.getTime(), 30 * 24 * 60 * MIN);
  clock.advance(30 * 24 * 60 * MIN - 1);
  assert.ok(await sessions.resolve(token));
  clock.advance(1);
  assert.equal(await sessions.resolve(token), null);
});

test('SessionService: revokeAllForUser only touches that user', async () => {
  const { sessions } = makeSessions();
  const a1 = await sessions.create('a');
  const a2 = await sessions.create('a');
  const b1 = await sessions.create('b');
  assert.equal(await sessions.revokeAllForUser('a'), 2);
  assert.equal(await sessions.resolve(a1.token), null);
  assert.equal(await sessions.resolve(a2.token), null);
  assert.ok(await sessions.resolve(b1.token));
  assert.equal(await sessions.revokeAllForUser('a'), 0);
});
