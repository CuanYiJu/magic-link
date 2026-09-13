import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hmac, newId, normalizeCode, normalizeEmail, randomCode, randomToken, safeEqualHex } from '../src/crypto.ts';

test('randomToken: 256 bits, base64url, unique', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 200; i++) {
    const t = randomToken();
    assert.match(t, /^[A-Za-z0-9_-]{43}$/);
    seen.add(t);
  }
  assert.equal(seen.size, 200);
  assert.equal(randomToken(16).length, 22);
});

test('randomCode: always exactly six digits, including leading zeros', () => {
  let sawLeadingZero = false;
  for (let i = 0; i < 5000; i++) {
    const c = randomCode();
    assert.match(c, /^\d{6}$/);
    if (c.startsWith('0')) sawLeadingZero = true;
  }
  assert.ok(sawLeadingZero, 'leading zeros should be padded, not dropped');
});

test('newId is a v4 UUID', () => {
  assert.match(newId(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('hmac is deterministic, keyed, and domain-separated by purpose', () => {
  const a = hmac('secret-one', 'link', 'value');
  assert.equal(a, hmac('secret-one', 'link', 'value'));
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, hmac('secret-two', 'link', 'value'));
  assert.notEqual(a, hmac('secret-one', 'code', 'value'));
  assert.notEqual(a, hmac('secret-one', 'session', 'value'));
  assert.notEqual(a, hmac('secret-one', 'link', 'valu'));
});

test('safeEqualHex compares digests without throwing on length mismatch', () => {
  const a = hmac('s', 'link', 'x');
  assert.equal(safeEqualHex(a, a), true);
  assert.equal(safeEqualHex(a, hmac('s', 'link', 'y')), false);
  assert.equal(safeEqualHex(a, a.slice(0, 10)), false);
  assert.equal(safeEqualHex('', ''), true);
});

test('normalizeEmail trims and lower-cases', () => {
  assert.equal(normalizeEmail('  Alice@Example.COM \n'), 'alice@example.com');
});

test('normalizeCode keeps digits only', () => {
  assert.equal(normalizeCode('123 456'), '123456');
  assert.equal(normalizeCode('12-34-56'), '123456');
  assert.equal(normalizeCode(' 1 2 3 4 5 6 '), '123456');
  assert.equal(normalizeCode('abc'), '');
});
