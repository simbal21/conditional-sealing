import type { FastifyInstance } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import {
  ShredExecutionError,
  type ShredExecutionRequest,
  type ShredExecutor,
} from "../shred/shred-executor.js";
import { TIER_BEHAVIOR_MATRIX } from "../types/tier-behavior.js";
import {
  getSubjectEscrowRecord,
  requireSubjectPrincipal,
  type SubjectEscrowRecord,
  type SubjectRouteContext,
} from "./routes-list-escrows.js";

// 32-byte commit hash hex form (`0x` + 64 hex). Security-audit-2026-05-14 TS-API-F-02.
const HCOMMIT_HEX_PATTERN = "^0x[0-9a-fA-F]{64}$";

export interface SubjectShredRequestBody {
  readonly request_reason_ref?: string;
}

/**
 * Optional composition-root injection: the real crypto-shred executor + the
 * resolver that turns the authenticated escrow record into a fully-PDA-derived
 * `ShredExecutionRequest`. When BOTH are present the route runs the real cascade
 * (T4.2); when absent the route keeps the in-memory `requested`-status behavior
 * so the existing tests + the default (synthetic) context stay green. Wave 5
 * wires these in via the context, so the context-defining file stays unedited.
 *
 * PLATFORM PRINCIPLE: the resolver is where per-PDA config (vault ref, PDA root,
 * reason digest) enters the cascade — nothing here is hardcoded.
 */
export interface SubjectShredExecutionResolver {
  resolve(input: {
    readonly user_id: string;
    readonly h_commit: string;
    readonly record: SubjectEscrowRecord;
    readonly body: SubjectShredRequestBody;
  }): Promise<ShredExecutionRequest> | ShredExecutionRequest;
}

/** The route context augmented with the optional executor wiring. The base
 *  `SubjectRouteContext` is owned elsewhere (Wave 5 single-owner); we extend it
 *  here without editing it. */
export type SubjectShredRouteContext = SubjectRouteContext & {
  readonly shredExecutor?: ShredExecutor;
  readonly resolveShredRequest?: SubjectShredExecutionResolver;
};

export async function createSubjectShredRequest(
  context: SubjectShredRouteContext,
  user_id: string,
  h_commit: string,
  body: SubjectShredRequestBody = {},
): Promise<Record<string, unknown>> {
  const record = getSubjectEscrowRecord(
    context,
    { user_id, session_id: "route", expires_at: new Date(Date.now() + 1000).toISOString() },
    h_commit,
  );
  // Subject-initiated shred is permitted only when the PDA `shredding_authority`
  // is Subject or Joint. Operator/Timelock/Disabled reject here — `Disabled`
  // PDAs (testament / archival / evidence) deliberately have no erasure path.
  if (record.shred_authority !== "Subject" && record.shred_authority !== "Joint") {
    throw new HttpProblem(
      problemFromCode("AUTH_FORBIDDEN", "subject_shred", {
        detail: "This PDA does not permit subject-initiated shred requests.",
        safe_refs: { h_commit, pda_id: record.pda_id, partner_id: record.partner_id },
      }),
    );
  }

  // Real cascade path: the composition root injected the executor + resolver.
  if (context.shredExecutor && context.resolveShredRequest) {
    const request = await context.resolveShredRequest.resolve({ user_id, h_commit, record, body });
    return runShredCascade(context.shredExecutor, request, {
      h_commit,
      pda_id: record.pda_id,
      partner_id: record.partner_id,
      shred_authority: record.shred_authority,
    });
  }

  // Default (no executor wired): in-memory request acknowledgement.
  return {
    h_commit,
    partner_id: record.partner_id,
    pda_id: record.pda_id,
    status: "requested",
    shred_authority: record.shred_authority,
    tier_behavior: TIER_BEHAVIOR_MATRIX.shred_request_auth.consumer,
    vault_deletion_status: "pending_on_chain_confirmation",
    blocked_future_reveal: false,
  };
}

/**
 * Run the executor cascade and map a `ShredExecutionError` to the right
 * Problem+JSON. Shared by the subject + partner routes' success/erroring shapes.
 */
async function runShredCascade(
  executor: ShredExecutor,
  request: ShredExecutionRequest,
  refs: { h_commit: string; pda_id: string; partner_id: string; shred_authority: string },
): Promise<Record<string, unknown>> {
  try {
    const result = await executor.execute(request);
    return {
      h_commit: result.hCommit,
      partner_id: refs.partner_id,
      pda_id: refs.pda_id,
      status: "finalized",
      shred_authority: refs.shred_authority,
      tier_behavior: TIER_BEHAVIOR_MATRIX.shred_request_auth.consumer,
      vault_deletion_status: "deleted",
      blocked_future_reveal: true,
      shredded_at: result.shreddedAt,
      shares_destroyed: result.sharesDestroyed,
      chain_tx_hash: result.chainTxHash,
      proof_shred: result.proofShred,
    };
  } catch (error) {
    if (error instanceof ShredExecutionError) {
      throw mapShredExecutionError(error, refs);
    }
    throw error;
  }
}

/**
 * Map a `ShredExecutionError` to a Problem+JSON. A `disabled` authority or an
 * active guardrail are client-visible refusals; mid-cascade failures surface as
 * server-side faults (the data is already partially/fully erased — never report
 * success).
 */
export function mapShredExecutionError(
  error: ShredExecutionError,
  refs: { h_commit: string; pda_id: string; partner_id: string },
): HttpProblem {
  const safe_refs = { h_commit: refs.h_commit, pda_id: refs.pda_id, partner_id: refs.partner_id };
  switch (error.context.reasonCode) {
    case "SHRED_AUTHORITY_DISABLED":
      return new HttpProblem(
        problemFromCode("AUTH_FORBIDDEN", "subject_shred", {
          detail: "Shred authority is disabled for this PDA — erasure is not permitted.",
          safe_refs,
        }),
      );
    case "SHRED_BLOCKED_POST_CHALLENGE_REVEAL":
    case "SHRED_BLOCKED_ALREADY_FINALIZED":
      // The mandatory NOT-post-challenge-reveal-in-progress guardrail (or an
      // already-finalized shred) blocks the request. CHAIN.SHRED_FINALIZED is
      // the locked 409 for the shred-vs-reveal interaction.
      return new HttpProblem(
        problemFromCode("CHAIN_SHRED_FINALIZED", "subject_shred", {
          detail: error.message,
          safe_refs,
        }),
      );
    default:
      // A mid-cascade failure (share destroy / vault delete / chain write /
      // audit). Surface a loud 503 — never a 2xx; the cascade did NOT complete.
      return new HttpProblem(
        problemFromCode("VAULT_UNAVAILABLE", "subject_shred", {
          detail: `Crypto-shred cascade failed at step ${error.context.step}: ${error.message}`,
          safe_refs,
          retryable: false,
        }),
      );
  }
}

export function registerCreateSubjectShredRequestRoute(app: FastifyInstance, context: SubjectShredRouteContext): void {
  app.post<{ Params: { h_commit: string }; Body: SubjectShredRequestBody }>(
    "/v1/subjects/me/escrows/:h_commit/shred-requests",
    {
      preHandler: context.preHandlers?.("createSubjectShredRequest"),
      schema: {
        params: {
          type: "object",
          required: ["h_commit"],
          properties: {
            h_commit: { type: "string", pattern: HCOMMIT_HEX_PATTERN },
          },
        },
      },
    },
    async (request, reply) =>
      reply
        .code(202)
        .send(
          await createSubjectShredRequest(
            context,
            requireSubjectPrincipal(request).user_id,
            request.params.h_commit,
            request.body ?? {},
          ),
        ),
  );
}
