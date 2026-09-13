import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SmtpMailer } from '../src/mailers/smtp.ts';

test('SmtpMailer hands the message to the transport unchanged', async () => {
  const sent: unknown[] = [];
  const mailer = new SmtpMailer({
    host: 'mail.kaiju.test',
    port: 587,
    transport: { sendMail: async (m: unknown) => { sent.push(m); return {}; } } as never,
  });
  await mailer.send({ to: 'a@b.co', from: '开局 <login@kaiju.test>', subject: 's', text: 't', html: '<p>h</p>' });
  assert.deepEqual(sent, [{ from: '开局 <login@kaiju.test>', to: 'a@b.co', subject: 's', text: 't', html: '<p>h</p>' }]);
});

test('SmtpMailer requires a host', () => {
  assert.throws(() => new SmtpMailer({ host: '', port: 25 }), /host is required/);
});

test('SmtpMailer.fromEnv: null without SMTP_HOST, defaults port 587, validates port', () => {
  assert.equal(SmtpMailer.fromEnv({}), null);
  assert.ok(SmtpMailer.fromEnv({ SMTP_HOST: 'mail.kaiju.test' }) instanceof SmtpMailer);
  assert.ok(SmtpMailer.fromEnv({ SMTP_HOST: 'mail.kaiju.test', SMTP_PORT: '465', SMTP_USER: 'u', SMTP_PASS: 'p' }));
  assert.throws(() => SmtpMailer.fromEnv({ SMTP_HOST: 'x', SMTP_PORT: 'abc' }), /SMTP_PORT/);
});

test('SmtpMailer surfaces transport failures', async () => {
  const mailer = new SmtpMailer({
    host: 'mail.kaiju.test',
    port: 25,
    transport: { sendMail: async () => { throw new Error('550 relay denied'); } } as never,
  });
  await assert.rejects(
    mailer.send({ to: 'a@b.co', from: 'x@kaiju.test', subject: 's', text: 't', html: 'h' }),
    /550 relay denied/,
  );
});
