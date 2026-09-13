import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHandlers } from '../src/http.ts';
import { credentialsFrom, makeService } from './helpers.ts';

const ORIGIN = 'https://kaiju.test';

function make() {
  const ctx = makeService();
  const handlers = createHandlers(ctx.service, { trustProxy: true });
  return { ...ctx, handlers };
}

function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, ...headers },
    body: JSON.stringify(body),
  });
}

function postForm(path: string, fields: Record<string, string>, headers: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ORIGIN, ...headers },
    body: new URLSearchParams(fields).toString(),
  });
}

test('POST /auth/magic-link accepts JSON and returns 202 with the normalised email', async () => {
  const { handlers, mailer } = make();
  const res = await handlers.requestLink(post('/auth/magic-link', { email: 'A@B.co' }));
  assert.equal(res.status, 202);
  assert.deepEqual(await res.json(), { status: 'sent', email: 'a@b.co' });
  assert.equal(mailer.sent.length, 1);
});

test('POST /auth/magic-link: invalid email → 400, foreign Origin → 403, GET → 405', async () => {
  const { handlers, mailer } = make();
  assert.equal((await handlers.requestLink(post('/auth/magic-link', { email: 'nope' }))).status, 400);
  const foreign = await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }, { Origin: 'https://evil.test' }));
  assert.equal(foreign.status, 403);
  const noOrigin = new Request(`${ORIGIN}/auth/magic-link`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.co' }),
  });
  assert.equal((await handlers.requestLink(noOrigin)).status, 403);
  assert.equal((await handlers.requestLink(new Request(`${ORIGIN}/auth/magic-link`))).status, 405);
  assert.equal(mailer.sent.length, 0);
});

test('Referer is accepted in place of Origin (older WeChat webviews)', async () => {
  const { handlers } = make();
  const res = await handlers.requestLink(
    new Request(`${ORIGIN}/auth/magic-link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Referer: `${ORIGIN}/login` },
      body: JSON.stringify({ email: 'a@b.co' }),
    }),
  );
  assert.equal(res.status, 202);
});

test('rate limited request → 429 with Retry-After', async () => {
  const { handlers } = make();
  for (let i = 0; i < 3; i++) await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const res = await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  assert.equal(res.status, 429);
  assert.ok(Number(res.headers.get('Retry-After')) > 0);
});

test('client IP comes from X-Forwarded-For when trustProxy is on', async () => {
  const { handlers, tokens } = make();
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }, { 'X-Forwarded-For': '203.0.113.5, 10.0.0.1' }));
  const [record] = [...tokens.records.values()];
  assert.equal(record?.requestIp, '203.0.113.5');
});

test('GET /auth/verify renders a self-submitting form and does not consume the link', async () => {
  const { handlers, mailer, tokens } = make();
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const { link } = credentialsFrom(mailer);
  const res = await handlers.verifyPage(new Request(`${link}&next=/e/abc`));
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/html/);
  const body = await res.text();
  assert.ok(body.includes('method="post"'));
  assert.ok(body.includes('name="next" value="/e/abc"'));
  const [record] = [...tokens.records.values()];
  assert.equal(record?.consumedAt, null);
  assert.equal((await handlers.verifyPage(new Request(`${ORIGIN}/auth/verify`))).status, 400);
});

test('GET /auth/verify escapes attacker-controlled query values', async () => {
  const { handlers } = make();
  const res = await handlers.verifyPage(new Request(`${ORIGIN}/auth/verify?token=${encodeURIComponent('"><script>x</script>')}`));
  const body = await res.text();
  assert.ok(!body.includes('<script>x</script>'));
  assert.ok(body.includes('&quot;&gt;&lt;script&gt;'));
});

test('POST /auth/verify (form) logs in, sets the cookie and redirects to a safe next', async () => {
  const { handlers, mailer } = make();
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const { token } = credentialsFrom(mailer);

  const res = await handlers.verifyLink(postForm('/auth/verify', { token, next: '/e/abc' }));
  assert.equal(res.status, 303);
  // First login goes to onboarding regardless of next.
  assert.equal(res.headers.get('Location'), '/onboarding');
  const cookie = res.headers.get('Set-Cookie') ?? '';
  assert.match(cookie, /^kaiju_session=.+; HttpOnly; SameSite=Lax; Secure$/);

  const me = await handlers.me(new Request(`${ORIGIN}/auth/me`, { headers: { Cookie: cookie.split(';')[0] as string } }));
  assert.equal(me.status, 200);
  const data = (await me.json()) as { userId: string };
  assert.ok(data.userId);

  // Returning user honours next, but not an absolute URL.
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const again = await handlers.verifyLink(postForm('/auth/verify', { token: credentialsFrom(mailer).token, next: '/e/abc' }));
  assert.equal(again.headers.get('Location'), '/e/abc');
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const evil = await handlers.verifyLink(postForm('/auth/verify', { token: credentialsFrom(mailer).token, next: 'https://evil.test' }));
  assert.equal(evil.headers.get('Location'), '/');
});

test('POST /auth/verify maps failures to status codes', async () => {
  const { handlers, mailer, clock } = make();
  assert.equal((await handlers.verifyLink(postForm('/auth/verify', { token: 'x' }))).status, 400);
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const { token } = credentialsFrom(mailer);
  await handlers.verifyLink(postForm('/auth/verify', { token }));
  const used = await handlers.verifyLink(postForm('/auth/verify', { token }));
  assert.equal(used.status, 410);
  assert.deepEqual(await used.json(), { status: 'used', message: '这个链接已经用过了，请重新发送登录邮件。' });

  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const fresh = credentialsFrom(mailer).token;
  clock.advance(16 * 60_000);
  assert.equal((await handlers.verifyLink(postForm('/auth/verify', { token: fresh }))).status, 410);
  assert.equal((await handlers.verifyLink(postForm('/auth/verify', { token: fresh }, { Origin: 'https://evil.test' }))).status, 403);
});

test('POST /auth/verify-code logs in with JSON and returns redirectTo', async () => {
  const { handlers, mailer } = make();
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const { code } = credentialsFrom(mailer);
  const res = await handlers.verifyCode(post('/auth/verify-code', { email: 'a@b.co', code, next: '/e/abc' }));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: 'ok', redirectTo: '/onboarding', isNew: true });
  assert.match(res.headers.get('Set-Cookie') ?? '', /^kaiju_session=/);

  const wrong = await handlers.verifyCode(post('/auth/verify-code', { email: 'a@b.co', code: '000000' }));
  assert.equal(wrong.status, 400);
});

test('too many wrong codes → 429', async () => {
  const { handlers, mailer } = make();
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const { code } = credentialsFrom(mailer);
  const wrong = code === '000000' ? '111111' : '000000';
  let last = 0;
  for (let i = 0; i < 5; i++) last = (await handlers.verifyCode(post('/auth/verify-code', { email: 'a@b.co', code: wrong }))).status;
  assert.equal(last, 429);
});

test('POST /auth/logout clears the cookie and kills the session', async () => {
  const { handlers, mailer } = make();
  await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  const login = await handlers.verifyCode(post('/auth/verify-code', { email: 'a@b.co', code: credentialsFrom(mailer).code }));
  const cookie = (login.headers.get('Set-Cookie') ?? '').split(';')[0] as string;

  const out = await handlers.logout(post('/auth/logout', {}, { Cookie: cookie }));
  assert.equal(out.status, 204);
  assert.match(out.headers.get('Set-Cookie') ?? '', /Max-Age=0/);
  const me = await handlers.me(new Request(`${ORIGIN}/auth/me`, { headers: { Cookie: cookie } }));
  assert.equal(me.status, 401);
  assert.equal(await handlers.getSession(new Request(`${ORIGIN}/`, { headers: { Cookie: cookie } })), null);
});

test('GET /auth/me without a cookie → 401', async () => {
  const { handlers } = make();
  assert.equal((await handlers.me(new Request(`${ORIGIN}/auth/me`))).status, 401);
});

test('mail provider failure → 503 with a friendly message and Retry-After, no detail leaked', async () => {
  const { handlers, service } = make();
  const svc = service as unknown as { deps: { mailer: unknown; logger: unknown } };
  svc.deps.mailer = { send: async () => { throw new Error('ResendMailer: 429 Too Many Requests {"message":"quota"}'); } };
  svc.deps.logger = { error: () => {} };
  const res = await handlers.requestLink(post('/auth/magic-link', { email: 'a@b.co' }));
  assert.equal(res.status, 503);
  assert.equal(res.headers.get('Retry-After'), '120');
  const body = (await res.json()) as { status: string; message: string };
  assert.equal(body.status, 'send_failed');
  assert.equal(body.message, '登录邮件暂时发不出去，请过几分钟再试。');
  assert.ok(!JSON.stringify(body).includes('Resend'), 'provider error text is not exposed');
});
