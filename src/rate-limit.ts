import type { Clock, RateLimiter, RateLimitResult, RateLimitRule } from './types.ts';
import { systemClock } from './types.ts';

/**
 * Sliding-window limiter kept in process memory. Good enough for a single
 * Vercel region at MVP scale; swap for a Postgres or Upstash implementation
 * of `RateLimiter` when the app runs in more than one instance.
 */
export class MemoryRateLimiter implements RateLimiter {
  private readonly hits = new Map<string, number[]>();

  private readonly clock: Clock;

  constructor(clock: Clock = systemClock) {
    this.clock = clock;
  }

  async hit(key: string, rule: RateLimitRule): Promise<RateLimitResult> {
    const now = this.clock.now().getTime();
    const windowStart = now - rule.windowMs;
    const recent = (this.hits.get(key) ?? []).filter((t) => t > windowStart);
    if (recent.length >= rule.max) {
      this.hits.set(key, recent);
      const oldest = recent[0] as number;
      return { allowed: false, remaining: 0, retryAfterMs: oldest + rule.windowMs - now };
    }
    recent.push(now);
    this.hits.set(key, recent);
    return { allowed: true, remaining: rule.max - recent.length, retryAfterMs: 0 };
  }

  /** Drop keys with no hits inside the largest window you use. */
  prune(maxWindowMs: number): void {
    const cutoff = this.clock.now().getTime() - maxWindowMs;
    for (const [key, times] of this.hits) {
      if (!times.some((t) => t > cutoff)) this.hits.delete(key);
    }
  }
}

/** Limiter that never blocks. For tests only. */
export const unlimited: RateLimiter = {
  async hit(_key, rule) {
    return { allowed: true, remaining: rule.max, retryAfterMs: 0 };
  },
};
