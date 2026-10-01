import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { HttpProblem, problemFromCode } from "../errors/index.js";

export interface IdempotencyRecord<T = unknown> {
  readonly scope: string;
  readonly key: string;
  readonly requestDigest: string;
  readonly statusCode: number;
  readonly responseBody: T;
  readonly expiresAtMs: number;
}

export class InMemoryIdempotencyStore {
  private readonly records = new Map<string, IdempotencyRecord>();

  async execute<T>(input: {
    readonly scope: string;
    readonly key: string;
    readonly rawRequestBody: Uint8Array;
    readonly nowMs?: number;
    readonly ttlMs?: number;
    readonly correlationId?: string;
    readonly run: () => Promise<{ statusCode: number; body: T }> | { statusCode: number; body: T };
  }): Promise<{ replayed: boolean; statusCode: number; body: T }> {
    const nowMs = input.nowMs ?? Date.now();
    const ttlMs = input.ttlMs ?? 24 * 60 * 60 * 1000;
    const digest = bytesToHex(sha256(input.rawRequestBody));
    const mapKey = `${input.scope}:${input.key}`;
    const existing = this.records.get(mapKey);
    if (existing && existing.expiresAtMs > nowMs) {
      if (existing.requestDigest !== digest) {
        throw new HttpProblem(
          problemFromCode("IDEMPOTENCY_KEY_CONFLICT", input.correlationId ?? "idempotency", {
            detail: "The same Idempotency-Key was replayed with a different request digest.",
          }),
        );
      }
      return {
        replayed: true,
        statusCode: existing.statusCode,
        body: existing.responseBody as T,
      };
    }
    const result = await input.run();
    this.records.set(mapKey, {
      scope: input.scope,
      key: input.key,
      requestDigest: digest,
      statusCode: result.statusCode,
      responseBody: result.body,
      expiresAtMs: nowMs + ttlMs,
    });
    return { replayed: false, statusCode: result.statusCode, body: result.body };
  }

  size(): number {
    return this.records.size;
  }
}

export function requestDigest(rawRequestBody: Uint8Array): string {
  return bytesToHex(sha256(rawRequestBody));
}
