// RFC 7807 Problem+JSON formatter — verbatim shape from S2-5 §1.4 lines 207-222.
//
// LOCKED at Phase A. Phase B/C/D throw via the `problemFromCode` helper to
// guarantee shape consistency. Custom titles/details may be passed via
// `partial`; required fields (`type`, `title`, `status`, `code`, `category`,
// `correlation_id`, `retryable`) are always populated.

import type { ErrorCategory } from "./categories.js";
import { ErrorCode, type ErrorCodeKey } from "./codes.js";

/**
 * Problem+JSON body shape — verbatim from §1.4 example.
 *
 * `safe_refs` is the bounded allow-list from §10.2 line 1014; redaction module
 * (`src/redaction/safe-refs.ts`) supplies the allow-list constants.
 */
export interface ProblemBody {
  type: string;
  title: string;
  status: number;
  code: string;
  category: ErrorCategory;
  detail?: string;
  correlation_id: string;
  retryable: boolean;
  safe_refs?: Record<string, string | number | boolean>;
}

const TYPE_BASE = "https://docs.cealis.local/problems/";

/**
 * Build a Problem+JSON body from a locked error code.
 *
 * Phase B/C/D usage:
 *   throw problemFromCode("ATTESTATION_LIT_ASSIGNMENT_MISSING", correlationId, {
 *     detail: "PDA inspection lookup at commit_block X returned no assignment",
 *     safe_refs: { authorizationId: "0x...", h_commit: "0x..." },
 *     retryable: false,
 *   });
 */
export function problemFromCode(
  key: ErrorCodeKey,
  correlation_id: string,
  partial: {
    detail?: string;
    safe_refs?: Record<string, string | number | boolean>;
    retryable?: boolean;
    statusOverride?: number;
  } = {},
): ProblemBody {
  const desc = ErrorCode[key];
  return {
    type: `${TYPE_BASE}${desc.code.toLowerCase().replace(/\./g, "/")}`,
    title: desc.title,
    status: partial.statusOverride ?? desc.httpStatus,
    code: desc.code,
    category: desc.category,
    detail: partial.detail,
    correlation_id,
    retryable: partial.retryable ?? false,
    safe_refs: partial.safe_refs,
  };
}

/**
 * Custom HTTP error class wrapping a Problem+JSON body.
 *
 * Fastify error hook unwraps and emits as `application/problem+json` body
 * with the body.status as the HTTP response status.
 */
export class HttpProblem extends Error {
  public readonly body: ProblemBody;

  constructor(body: ProblemBody) {
    super(`${body.code}: ${body.title}`);
    this.name = "HttpProblem";
    this.body = body;
  }
}

/**
 * Throw helper — short-hand for Phase B/C/D route handlers.
 */
export function throwProblem(
  key: ErrorCodeKey,
  correlation_id: string,
  partial?: Parameters<typeof problemFromCode>[2],
): never {
  throw new HttpProblem(problemFromCode(key, correlation_id, partial));
}
