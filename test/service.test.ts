import { test } from 'node:test';
import assert from 'node:assert/strict';
import { credentialsFrom, makeService } from './helpers.ts';
import { safeRelativePath } from '../src/service.ts';

const MIN = 60_000;

test('requestLink sends one email carrying a link and a 6-digit code', async () => {
  const { service, mailer } = makeService();
  const result = await service.requestLink({ email: '  Alice@Example.com ' });
  assert.deepEqual(result, { status: 'sent', email: 'alice@example.com' });
  assert.equal(mailer.sent.length, 1);
  const { token, code, link } = credentialsFrom(mailer);
  assert.match(mailer.last().subject, /登录验证码 \d{6}/);
  assert.equal(mailer.last().to, 'alice@example.com');
  assert.ok(link.startsWith('https://kaiju.test/auth/verify?token='));
  assert.ok(token.length >= 40);
  assert.match(code, /^\d{6}$/);
  assert.ok(mailer.last().html.includes(code));
});

test('requestLink rejects malformed addresses without sending', async () => {
  const { service, mailer } = makeService();
  assert.deepEqual(await service.requestLink({ email: 'not-an-email' }), { status: 'invalid_email' });
  assert.deepEqual(await service.requestLink({ email: '' }), { status: 'invalid_email' });
  assert.equal(mailer.sent.length, 0);
});

test('raw token and code are never stored, only keyed hashes', async () => {
  const { service, mailer, tokens } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const { token, code } = credentialsFrom(mailer);
  const [record] = [...tokens.records.values()];
  assert.ok(record);
  const dump = JSON.stringify(record);
  assert.ok(!dump.includes(token));
  assert.ok(!dump.includes(code));
  assert.match(record.tokenHash, /^[0-9a-f]{64}$/);
  assert.match(record.codeHash, /^[0-9a-f]{64}$/);
});

test('link logs in exactly once and creates the user', async () => {
  const { service, mailer, users } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const { token } = credentialsFrom(mailer);

  const first = await service.verifyLink(token, { ip: '1.1.1.1', userAgent: 'ua' });
  assert.equal(first.status, 'ok');
  if (first.status !== 'ok') return;
  assert.equal(first.user.email, 'a@b.co');
  assert.equal(first.user.isNew, true);
  assert.equal(users.users.size, 1);
  assert.ok(first.sessionToken.length >= 40);
  assert.equal(first.session.ip, '1.1.1.1');
  assert.equal(first.session.userAgent, 'ua');

  const second = await service.verifyLink(token);
  assert.deepEqual(second, { status: 'used' });
});

test('code logs in and burns the link from the same email', async () => {
  const { service, mailer } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const { token, code } = credentialsFrom(mailer);

  const viaCode = await service.verifyCode('A@B.CO', `${code.slice(0, 3)} ${code.slice(3)}`);
  assert.equal(viaCode.status, 'ok');
  assert.deepEqual(await service.verifyLink(token), { status: 'used' });
});

test('link burns the code from the same email', async () => {
  const { service, mailer } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const { token, code } = credentialsFrom(mailer);
  assert.equal((await service.verifyLink(token)).status, 'ok');
  // Nothing active remains for the email, so the code reads as invalid.
  assert.deepEqual(await service.verifyCode('a@b.co', code), { status: 'invalid' });
});

test('second login for the same email reuses the user and is not new', async () => {
  const { service, mailer, users } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const r1 = await service.verifyLink(credentialsFrom(mailer).token);
  await service.requestLink({ email: 'a@b.co' });
  const r2 = await service.verifyLink(credentialsFrom(mailer).token);
  assert.equal(r1.status, 'ok');
  assert.equal(r2.status, 'ok');
  if (r1.status !== 'ok' || r2.status !== 'ok') return;
  assert.equal(r1.user.id, r2.user.id);
  assert.equal(r2.user.isNew, false);
  assert.equal(users.users.size, 1);
  assert.ok(users.users.get(r1.user.id)?.lastLoginAt);
});

test('link and code expire after 15 minutes', async () => {
  const { service, mailer, clock } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const { token, code } = credentialsFrom(mailer);
  clock.advance(15 * MIN + 1);
  assert.deepEqual(await service.verifyLink(token), { status: 'expired' });
  assert.deepEqual(await service.verifyCode('a@b.co', code), { status: 'expired' });
});

test('link still works one second before expiry', async () => {
  const { service, mailer, clock } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  clock.advance(15 * MIN - 1000);
  assert.equal((await service.verifyLink(credentialsFrom(mailer).token)).status, 'ok');
});

test('a newer request invalidates the previous link and code', async () => {
  const { service, mailer } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const old = credentialsFrom(mailer);
  await service.requestLink({ email: 'a@b.co' });
  const fresh = credentialsFrom(mailer);
  assert.deepEqual(await service.verifyLink(old.token), { status: 'used' });
  // Old code no longer matches the only active record.
  assert.deepEqual(await service.verifyCode('a@b.co', old.code), { status: 'invalid' });
  assert.equal((await service.verifyCode('a@b.co', fresh.code)).status, 'ok');
});

test('five wrong codes burn the pending login, including its link', async () => {
  const { service, mailer } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const { token, code } = credentialsFrom(mailer);
  const wrong = code === '000000' ? '111111' : '000000';
  for (let i = 0; i < 4; i++) {
    assert.deepEqual(await service.verifyCode('a@b.co', wrong), { status: 'invalid' });
  }
  assert.deepEqual(await service.verifyCode('a@b.co', wrong), { status: 'too_many_attempts' });
  // Even the right code is dead now, and so is the link.
  assert.deepEqual(await service.verifyCode('a@b.co', code), { status: 'invalid' });
  assert.deepEqual(await service.verifyLink(token), { status: 'used' });
});

test('garbage tokens and codes are rejected without touching stores', async () => {
  const { service } = makeService();
  assert.deepEqual(await service.verifyLink(''), { status: 'invalid' });
  assert.deepEqual(await service.verifyLink('short'), { status: 'invalid' });
  assert.deepEqual(await service.verifyLink('x'.repeat(50) + '!'), { status: 'invalid' });
  assert.deepEqual(await service.verifyCode('a@b.co', '12345'), { status: 'invalid' });
  assert.deepEqual(await service.verifyCode('nope', '123456'), { status: 'invalid' });
  assert.deepEqual(await service.verifyCode('a@b.co', '123456'), { status: 'invalid' });
});

test('per-email rate limit: 3 per 10 minutes, then retry-after', async () => {
  const { service, clock, mailer } = makeService();
  for (let i = 0; i < 3; i++) assert.equal((await service.requestLink({ email: 'a@b.co' })).status, 'sent');
  const blocked = await service.requestLink({ email: 'a@b.co' });
  assert.equal(blocked.status, 'rate_limited');
  if (blocked.status === 'rate_limited') assert.ok(blocked.retryAfterMs > 0 && blocked.retryAfterMs <= 10 * MIN);
  assert.equal(mailer.sent.length, 3);
  // Case and whitespace do not open a second bucket.
  assert.equal((await service.requestLink({ email: ' A@B.CO ' })).status, 'rate_limited');
  clock.advance(10 * MIN + 1);
  assert.equal((await service.requestLink({ email: 'a@b.co' })).status, 'sent');
});

test('per-email daily cap: 10 per day', async () => {
  const { service, clock } = makeService();
  for (let i = 0; i < 10; i++) {
    if (i % 3 === 0 && i > 0) clock.advance(10 * MIN + 1);
    assert.equal((await service.requestLink({ email: 'a@b.co' })).status, 'sent', `send #${i + 1}`);
  }
  clock.advance(10 * MIN + 1);
  assert.equal((await service.requestLink({ email: 'a@b.co' })).status, 'rate_limited');
});

test('per-IP limit applies across different emails', async () => {
  const { service } = makeService();
  for (let i = 0; i < 10; i++) {
    assert.equal((await service.requestLink({ email: `u${i}@b.co`, ip: '9.9.9.9' })).status, 'sent');
  }
  assert.equal((await service.requestLink({ email: 'u99@b.co', ip: '9.9.9.9' })).status, 'rate_limited');
  assert.equal((await service.requestLink({ email: 'u99@b.co', ip: '8.8.8.8' })).status, 'sent');
});

test('verification attempts are rate limited per IP', async () => {
  const { service } = makeService();
  for (let i = 0; i < 30; i++) {
    assert.equal((await service.verifyCode('a@b.co', '123456', { ip: '7.7.7.7' })).status, 'invalid');
  }
  assert.equal((await service.verifyCode('a@b.co', '123456', { ip: '7.7.7.7' })).status, 'rate_limited');
});

test('session fixation: the pre-login session is revoked on login', async () => {
  const { service, mailer, sessions } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const first = await service.verifyLink(credentialsFrom(mailer).token);
  assert.equal(first.status, 'ok');
  if (first.status !== 'ok') return;
  assert.ok(await service.getSession(first.sessionToken));

  await service.requestLink({ email: 'b@b.co' });
  const second = await service.verifyLink(credentialsFrom(mailer).token, { existingSessionToken: first.sessionToken });
  assert.equal(second.status, 'ok');
  if (second.status !== 'ok') return;
  assert.notEqual(second.sessionToken, first.sessionToken);
  assert.equal(await service.getSession(first.sessionToken), null);
  assert.equal((await service.getSession(second.sessionToken))?.userId, second.user.id);
  assert.equal(sessions.records.size, 2);
});

test('session lasts 30 days of inactivity, slides on use, and logout revokes it', async () => {
  const { service, mailer, clock } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const login = await service.verifyLink(credentialsFrom(mailer).token);
  assert.equal(login.status, 'ok');
  if (login.status !== 'ok') return;

  clock.advance(29 * 24 * 60 * MIN);
  const active = await service.getSession(login.sessionToken);
  assert.ok(active);
  assert.ok(active.setCookie, 'a visit after a day re-issues the cookie');
  clock.advance(29 * 24 * 60 * MIN);
  assert.ok(await service.getSession(login.sessionToken), 'extended by the earlier visit');
  clock.advance(31 * 24 * 60 * MIN);
  assert.equal(await service.getSession(login.sessionToken), null, '30 idle days end it');

  await service.requestLink({ email: 'a@b.co' });
  const again = await service.verifyLink(credentialsFrom(mailer).token);
  assert.equal(again.status, 'ok');
  if (again.status !== 'ok') return;
  const { cookie } = await service.logout(again.sessionToken);
  assert.equal(await service.getSession(again.sessionToken), null);
  assert.match(cookie, /Max-Age=0/);
  // Logging out with no or a bogus token is a no-op, not an error.
  await service.logout(null);
  await service.logout('bogus');
});

test('session cookie has the attributes from plan §4.2', async () => {
  const { service, mailer } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const login = await service.verifyLink(credentialsFrom(mailer).token);
  assert.equal(login.status, 'ok');
  if (login.status !== 'ok') return;
  assert.match(login.cookie, /^kaiju_session=[A-Za-z0-9_-]+; Path=\/; Max-Age=2592000; Expires=Mon, 12 Oct 2026 12:00:00 GMT; HttpOnly; SameSite=Lax; Secure$/);
});

test('sliding expiry can be turned off: then the session ends 30 days after login regardless of use', async () => {
  const { service, mailer, clock } = makeService({ sessionSliding: false });
  await service.requestLink({ email: 'a@b.co' });
  const login = await service.verifyLink(credentialsFrom(mailer).token);
  assert.equal(login.status, 'ok');
  if (login.status !== 'ok') return;
  clock.advance(29 * 24 * 60 * MIN);
  const active = await service.getSession(login.sessionToken);
  assert.ok(active);
  assert.equal(active.setCookie, undefined);
  clock.advance(2 * 24 * 60 * MIN);
  assert.equal(await service.getSession(login.sessionToken), null);
});

test('banned users cannot log in', async () => {
  const { service, mailer, users } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  const login = await service.verifyLink(credentialsFrom(mailer).token);
  assert.equal(login.status, 'ok');
  if (login.status !== 'ok') return;
  users.users.get(login.user.id)!.banned = true;
  await service.requestLink({ email: 'a@b.co' });
  assert.deepEqual(await service.verifyLink(credentialsFrom(mailer).token), { status: 'forbidden' });
});

test('resolveNextPath: onboarding for new users, safe relative paths otherwise', () => {
  const { service } = makeService();
  const fresh = { id: 'u', email: 'a@b.co', isNew: true };
  const known = { id: 'u', email: 'a@b.co', isNew: false };
  assert.equal(service.resolveNextPath('/e/abc', fresh), '/onboarding');
  assert.equal(service.resolveNextPath('/e/abc', known), '/e/abc');
  assert.equal(service.resolveNextPath(null, known), '/');
  assert.equal(service.resolveNextPath('https://evil.test', known), '/');
  assert.equal(service.resolveNextPath('//evil.test/x', known), '/');
});

test('safeRelativePath blocks open-redirect shapes', () => {
  assert.equal(safeRelativePath('/e/abc?x=1#y'), '/e/abc?x=1#y');
  assert.equal(safeRelativePath('/'), '/');
  for (const bad of ['', 'e/abc', 'https://x.test', '//x.test', '/\\x.test', '/x\\y', '/x\ny', 'javascript:alert(1)', '/'.padEnd(3000, 'a')]) {
    assert.equal(safeRelativePath(bad), null, JSON.stringify(bad));
  }
});

test('purgeExpired removes stale tokens and sessions', async () => {
  const { service, mailer, clock, tokens, sessions } = makeService();
  await service.requestLink({ email: 'a@b.co' });
  await service.requestLink({ email: 'b@b.co' });
  const login = await service.verifyLink(credentialsFrom(mailer).token);
  assert.equal(login.status, 'ok');
  clock.advance(16 * MIN);
  assert.deepEqual(await service.purgeExpired(), { tokens: 2, sessions: 0 });
  assert.equal(tokens.records.size, 0);
  clock.advance(31 * 24 * 60 * MIN);
  assert.deepEqual(await service.purgeExpired(), { tokens: 0, sessions: 1 });
  assert.equal(sessions.records.size, 0);
});

test('config guards: short secret, non-https base URL, insecure cookie off localhost', async () => {
  assert.throws(() => makeService({ secret: 'short' }), /at least 32/);
  assert.throws(() => makeService({ baseUrl: 'http://kaiju.test' }), /https/);
  assert.throws(() => makeService({ cookieSecure: false }), /localhost/);
  const local = makeService({ baseUrl: 'http://localhost:3000' });
  assert.equal(local.config.cookieSecure, false);
});

test('mailer failure: send_failed, nothing left pending, cause logged, next attempt works', async () => {
  const { service, mailer, tokens } = makeService();
  const logged: unknown[] = [];
  const flaky = Object.assign(service as unknown as { deps: { mailer: unknown; logger: unknown } });
  // Reach into deps for this test only: swap the mailer for one that fails once.
  const original = flaky.deps.mailer;
  let calls = 0;
  flaky.deps.mailer = { send: async () => { calls++; throw new Error('Resend: 429 Too Many Requests daily quota exceeded'); } };
  flaky.deps.logger = { error: (m: string, meta: unknown) => logged.push([m, meta]) };

  const result = await service.requestLink({ email: 'a@b.co' });
  assert.equal(calls, 1);
  assert.deepEqual(result, { status: 'send_failed', reason: 'Resend: 429 Too Many Requests daily quota exceeded' });
  assert.equal(logged.length, 1);
  assert.match(String((logged[0] as unknown[])[0]), /failed to send/);
  // The record exists but is burned, so the (unsent) link and code can never log in.
  assert.equal(tokens.records.size, 1);
  assert.ok([...tokens.records.values()][0]?.consumedAt);
  assert.deepEqual(await service.verifyCode('a@b.co', '000000'), { status: 'invalid' });

  flaky.deps.mailer = original;
  const again = await service.requestLink({ email: 'a@b.co' });
  assert.equal(again.status, 'sent');
  assert.equal((await service.verifyLink(credentialsFrom(mailer).token)).status, 'ok');
});
