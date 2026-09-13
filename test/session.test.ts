import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SessionService, readCookie, serializeClearedCookie, serializeSessionCookie } from '../src/session.ts';
import { resolveConfig, type MagicLinkConfigInput } from '../src/config.ts';
import { MemorySessionStore } from '../src/stores/memory.ts';
import { FakeClock, SECRET } from './helpers.ts';

const MIN = 60_000;

test('serializeSessionCookie emits the plan §4.2 attributes, Max-Age and Expires, and encodes the value', () => {
  const now = new Date('2026-09-12T12:00:00Z');
  const c = serializeSessionCookie('a b', { name: 'kaiju_session', secure: true, maxAge: 2592000, now });
  assert.equal(c, 'kaiju_session=a%20b; Path=/; Max-Age=2592000; Expires=Mon, 12 Oct 2026 12:00:00 GMT; HttpOnly; SameSite=Lax; Secure');
  const insecure = serializeSessionCookie('t', { name: 's', secure: false, maxAge: 1 });
  assert.ok(!insecure.includes('Secure'));
  assert.match(insecure, /Expires=[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT/);
  assert.equal(serializeClearedCookie('s', true), 's=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure');
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

function makeSessions(overrides: Partial<MagicLinkConfigInput> = {}) {
  const clock = new FakeClock();
  const store = new MemorySessionStore();
  const config = resolveConfig({ secret: SECRET, baseUrl: 'https://kaiju.test', emailFrom: 'x <x@kaiju.test>', ...overrides });
  return { clock, store, config, sessions: new SessionService(store, config, clock) };
}

const DAY = 24 * 60 * MIN;

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

test('SessionService: initial expiry is 30 days; without sliding it is absolute', async () => {
  const { sessions, clock } = makeSessions({ sessionSliding: false });
  const { token, session } = await sessions.create('u1');
  assert.equal(session.expiresAt.getTime() - session.createdAt.getTime(), 30 * DAY);
  clock.advance(30 * DAY - 1);
  const active = await sessions.resolve(token);
  assert.ok(active);
  assert.equal(active.renewed, false);
  clock.advance(1);
  assert.equal(await sessions.resolve(token), null);
});

test('SessionService: sliding expiry renews at most once a day and moves expiresAt forward', async () => {
  const { sessions, store, clock } = makeSessions();
  const { token, session } = await sessions.create('u1');
  const t0 = session.expiresAt.getTime();

  clock.advance(23 * 60 * MIN);
  let r = await sessions.resolve(token);
  assert.equal(r?.renewed, false, 'less than a day since login: no renewal');
  assert.equal(store.records.get(session.id)?.expiresAt.getTime(), t0);

  clock.advance(2 * 60 * MIN);
  r = await sessions.resolve(token);
  assert.equal(r?.renewed, true, 'a day has passed: renewed');
  const t1 = store.records.get(session.id)!.expiresAt.getTime();
  assert.equal(t1, clock.now().getTime() + 30 * DAY);
  assert.equal(r?.session.expiresAt.getTime(), t1, 'returned record reflects the new expiry');

  clock.advance(5 * MIN);
  r = await sessions.resolve(token);
  assert.equal(r?.renewed, false, 'just renewed: not again');
  assert.equal(store.records.get(session.id)?.expiresAt.getTime(), t1);
});

test('SessionService: a user active every week stays logged in past 30 days, but not past the absolute cap', async () => {
  const { sessions, clock } = makeSessions({ sessionAbsoluteMaxMs: 90 * DAY });
  const { token } = await sessions.create('u1');
  for (let week = 1; week <= 12; week++) {
    clock.advance(7 * DAY);
    assert.ok(await sessions.resolve(token), `week ${week}`);
  }
  // Day 84 → next visit at day 91 is past the 90-day cap.
  clock.advance(7 * DAY);
  assert.equal(await sessions.resolve(token), null);
});

test('SessionService: renewal never extends past createdAt + absolute max', async () => {
  const { sessions, store, clock } = makeSessions({ sessionAbsoluteMaxMs: 40 * DAY });
  const { token, session } = await sessions.create('u1');
  clock.advance(20 * DAY);
  const r = await sessions.resolve(token);
  assert.equal(r?.renewed, true);
  assert.equal(store.records.get(session.id)?.expiresAt.getTime(), session.createdAt.getTime() + 40 * DAY);
});

test('SessionService.cookie: Max-Age matches the session expiry, not always 30 days', async () => {
  const { sessions, clock } = makeSessions({ sessionAbsoluteMaxMs: 40 * DAY });
  const { token } = await sessions.create('u1');
  clock.advance(20 * DAY);
  const r = await sessions.resolve(token);
  assert.ok(r);
  assert.match(sessions.cookie(token, r.session.expiresAt), /Max-Age=1728000;/); // 20 days left of the 40-day cap
  assert.match(sessions.cookie(token), /Max-Age=2592000;/);
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
