import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";

export interface RateLimitResult {
  readonly allowed: boolean;
  readonly limit: number;
  readonly remaining: number;
  readonly resetSeconds: number;
  readonly retryAfterSeconds?: number;
}

/**
 * Rate-limit store contract.
 *
 * `check()` returns Promise<RateLimitResult> because the Postgres impl must
 * hit the DB. InMemory is async-shaped too so the middleware doesn't branch
 * by store kind — composition root picks the impl, middleware always awaits.
 * Previously the contract was sync and the Postgres impl threw at runtime —
 * see dw-quality-2 R2b-2 NEEDS-CHANGES (SHOULD-FIX-1, Rule-12 honesty).
 */
export interface RateLimitStore {
  check(input: {
    readonly key: string;
    readonly limit: number;
    readonly windowMs: number;
    readonly nowMs?: number;
  }): Promise<RateLimitResult>;
}

export class InMemoryRateLimitStore implements RateLimitStore {
  private readonly buckets = new Map<string, { count: number; resetAtMs: number }>();

  async check(input: {
    readonly key: string;
    readonly limit: number;
    readonly windowMs: number;
    readonly nowMs?: number;
  }): Promise<RateLimitResult> {
    const nowMs = input.nowMs ?? Date.now();
    const current = this.buckets.get(input.key);
    const bucket =
      current && current.resetAtMs > nowMs
        ? current
        : { count: 0, resetAtMs: nowMs + input.windowMs };
    bucket.count += 1;
    this.buckets.set(input.key, bucket);
    const resetSeconds = Math.ceil((bucket.resetAtMs - nowMs) / 1000);
    const remaining = Math.max(input.limit - bucket.count, 0);
    if (bucket.count > input.limit) {
      return {
        allowed: false,
        limit: input.limit,
        remaining: 0,
        resetSeconds,
        retryAfterSeconds: resetSeconds,
      };
    }
    return { allowed: true, limit: input.limit, remaining, resetSeconds };
  }
}

export function createRateLimitPreHandler(options: {
  readonly store: RateLimitStore;
  readonly limit: number;
  readonly windowMs: number;
  readonly keyFromRequest: (request: FastifyRequest) => string;
  readonly nowMs?: () => number;
}): preHandlerHookHandler {
  return (request: FastifyRequest, reply: FastifyReply, done): void => {
    options.store
      .check({
        key: options.keyFromRequest(request),
        limit: options.limit,
        windowMs: options.windowMs,
        nowMs: options.nowMs?.() ?? Date.now(),
      })
      .then((result) => {
        setRateLimitHeaders(reply, result);
        if (!result.allowed) {
          done(
            new HttpProblem(
              problemFromCode("RATE_LIMIT_EXCEEDED", request.id, {
                detail: "Rate limit exceeded for this credential or source.",
                retryable: true,
              }),
            ),
          );
          return;
        }
        done();
      })
      .catch((error: unknown) => done(error as Error));
  };
}

export function setRateLimitHeaders(reply: Pick<FastifyReply, "header">, result: RateLimitResult): void {
  reply.header("X-RateLimit-Limit", String(result.limit));
  reply.header("X-RateLimit-Remaining", String(result.remaining));
  reply.header("X-RateLimit-Reset", String(result.resetSeconds));
  if (result.retryAfterSeconds !== undefined) {
    reply.header("Retry-After", String(result.retryAfterSeconds));
  }
}
