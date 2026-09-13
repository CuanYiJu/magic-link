import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ResendMailer } from '../src/mailers/resend.ts';

const message = { to: 'a@b.co', from: '开局 <login@kaiju.test>', subject: 's', text: 't', html: '<p>h</p>' };

test('ResendMailer posts the expected payload with the bearer key', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const mailer = new ResendMailer({
    apiKey: 're_test',
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response('{"id":"x"}', { status: 200 });
    }) as typeof fetch,
  });
  await mailer.send(message);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, 'https://api.resend.com/emails');
  assert.equal((calls[0]!.init.headers as Record<string, string>).Authorization, 'Bearer re_test');
  const body = JSON.parse(String(calls[0]!.init.body)) as Record<string, unknown>;
  assert.deepEqual(body.to, ['a@b.co']);
  assert.equal(body.from, message.from);
  assert.equal(body.subject, 's');
  assert.equal(body.html, '<p>h</p>');
  assert.equal(body.text, 't');
});

test('ResendMailer surfaces non-2xx responses with status and body', async () => {
  const mailer = new ResendMailer({
    apiKey: 're_test',
    fetch: (async () => new Response('{"message":"daily quota exceeded"}', { status: 429, statusText: 'Too Many Requests' })) as typeof fetch,
  });
  await assert.rejects(mailer.send(message), /429 Too Many Requests .*daily quota exceeded/);
});

test('ResendMailer requires an API key', () => {
  assert.throws(() => new ResendMailer({ apiKey: '' }), /apiKey is required/);
});

test('ResendMailer calls the global fetch as a plain function (Cloudflare Workers "Illegal invocation" regression)', async () => {
  // Workers' fetch throws when invoked with any `this` other than the global.
  // Emulate that strictness on Node's global so a cached/bound call is caught here.
  const original = globalThis.fetch;
  const seen: string[] = [];
  globalThis.fetch = async function (this: unknown, input: string | URL | Request) {
    if (this !== undefined && this !== globalThis) {
      throw new TypeError('Illegal invocation: function called with incorrect `this` reference');
    }
    seen.push(String(input));
    return new Response('{"id":"x"}', { status: 200 });
  } as typeof fetch;
  try {
    const mailer = new ResendMailer({ apiKey: 're_test' }); // no fetch override: uses the global
    await mailer.send(message);
    assert.deepEqual(seen, ['https://api.resend.com/emails']);
  } finally {
    globalThis.fetch = original;
  }
});

test('ResendMailer picks up a fetch global that is replaced after construction', async () => {
  // Workers and some test harnesses swap the global; a constructor-time cache would miss it.
  const original = globalThis.fetch;
  const mailer = new ResendMailer({ apiKey: 're_test' });
  let used = false;
  globalThis.fetch = (async () => { used = true; return new Response('{}', { status: 200 }); }) as typeof fetch;
  try {
    await mailer.send(message);
    assert.equal(used, true);
  } finally {
    globalThis.fetch = original;
  }
});
