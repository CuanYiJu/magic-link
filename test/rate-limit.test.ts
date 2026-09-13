import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryRateLimiter, unlimited } from '../src/rate-limit.ts';
import { FakeClock } from './helpers.ts';

const rule = { max: 3, windowMs: 10_000 };

test('allows up to max hits in the window, then blocks with retryAfterMs', async () => {
  const clock = new FakeClock();
  const rl = new MemoryRateLimiter(clock);
  assert.deepEqual(await rl.hit('k', rule), { allowed: true, remaining: 2, retryAfterMs: 0 });
  clock.advance(1000);
  assert.deepEqual(await rl.hit('k', rule), { allowed: true, remaining: 1, retryAfterMs: 0 });
  clock.advance(1000);
  assert.deepEqual(await rl.hit('k', rule), { allowed: true, remaining: 0, retryAfterMs: 0 });
  const blocked = await rl.hit('k', rule);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterMs, 8000, 'oldest hit was 2s ago in a 10s window');
});

test('the window slides: the oldest hit falling out frees one slot', async () => {
  const clock = new FakeClock();
  const rl = new MemoryRateLimiter(clock);
  await rl.hit('k', rule);
  clock.advance(5000);
  await rl.hit('k', rule);
  await rl.hit('k', rule);
  assert.equal((await rl.hit('k', rule)).allowed, false);
  clock.advance(5001);
  assert.equal((await rl.hit('k', rule)).allowed, true);
  assert.equal((await rl.hit('k', rule)).allowed, false);
});

test('blocked attempts do not extend the block', async () => {
  const clock = new FakeClock();
  const rl = new MemoryRateLimiter(clock);
  for (let i = 0; i < 3; i++) await rl.hit('k', rule);
  for (let i = 0; i < 50; i++) {
    clock.advance(100);
    assert.equal((await rl.hit('k', rule)).allowed, false);
  }
  clock.advance(5001);
  assert.equal((await rl.hit('k', rule)).allowed, true);
});

test('keys are independent', async () => {
  const rl = new MemoryRateLimiter(new FakeClock());
  for (let i = 0; i < 3; i++) await rl.hit('a', rule);
  assert.equal((await rl.hit('a', rule)).allowed, false);
  assert.equal((await rl.hit('b', rule)).allowed, true);
});

test('prune drops keys with no recent hits', async () => {
  const clock = new FakeClock();
  const rl = new MemoryRateLimiter(clock);
  await rl.hit('old', rule);
  clock.advance(20_000);
  await rl.hit('new', rule);
  rl.prune(10_000);
  assert.equal((await rl.hit('old', rule)).remaining, 2, 'old key was reset');
  assert.equal((await rl.hit('new', rule)).remaining, 1, 'new key kept its hit');
});

test('unlimited never blocks', async () => {
  for (let i = 0; i < 100; i++) assert.equal((await unlimited.hit('k', { max: 1, windowMs: 1 })).allowed, true);
});
