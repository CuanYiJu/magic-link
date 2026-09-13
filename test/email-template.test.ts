import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderLoginEmail } from '../src/email-template.ts';

const base = {
  to: 'a@b.co',
  from: '开局 <login@kaiju.test>',
  appName: '开局',
  link: 'https://kaiju.test/auth/verify?token=abc',
  code: '012345',
  ttlMinutes: 15,
};

test('subject carries the app name and the code (visible in WeChat notifications)', () => {
  const m = renderLoginEmail(base);
  assert.equal(m.subject, '开局 登录验证码 012345');
  assert.equal(m.to, 'a@b.co');
  assert.equal(m.from, base.from);
});

test('text and html both contain the link, the code, the TTL and the "ignore if not you" line', () => {
  const m = renderLoginEmail(base);
  for (const body of [m.text, m.html]) {
    assert.ok(body.includes(base.link));
    assert.ok(body.includes('012345'));
    assert.ok(body.includes('15 分钟'));
    assert.ok(body.includes('忽略这封邮件'));
    assert.ok(body.includes('Sign in to 开局'), 'English summary line');
  }
  assert.match(m.html, /<a href="https:\/\/kaiju\.test\/auth\/verify\?token=abc"/);
  assert.ok(m.html.includes('lang="zh-CN"'));
});

test('html escapes attacker-influenced values', () => {
  const m = renderLoginEmail({ ...base, appName: '<b>x</b>&"', link: 'https://kaiju.test/?t="><img src=x>' });
  assert.ok(!m.html.includes('<b>x</b>'));
  assert.ok(m.html.includes('&lt;b&gt;x&lt;/b&gt;&amp;&quot;'));
  assert.ok(!m.html.includes('"><img src=x>'));
});
