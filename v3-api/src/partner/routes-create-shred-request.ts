import type { FastifyInstance } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import {
  ShredExecutionError,
  type ShredExecutionRequest,
  type ShredExecutor,
} from "../shred/shred-executor.js";
import { TIER_BEHAVIOR_MATRIX } from "../types/tier-behavior.js";
import { getPartnerEscrow } from "./routes-get-escrow.js";
import {
  getPartnerPdaRecord,
  requirePartnerPrincipal,
  type PartnerPdaRecord,
  type PartnerRouteContext,
} from "./routes-list-pdas.js";

// 32-byte commit hash hex form (`0x` + 64 hex). Used as URL-param shape guard
// per security-audit-2026-05-14 TS-API-F-02 — malformed h_commit must be rejected
// before any handler body / DB lookup runs.
const HCOMMIT_HEX_PATTERN = "^0x[0-9a-fA-F]{64}$";

export interface ShredRequestBody {
  readonly request_reason_ref?: string;
  readonly actor_role?: "partner" | "joint" | "operator";
}

/**
 * Optional composition-root injection (see the subject route for the symmetric
 * shape). When the executor + resolver are present the partner route runs the
 * real crypto-shred cascade (T4.2); when absent it keeps the in-memory
 * `requested`-status behavior so existing tests + the default context stay green.
 * Wave 5 wires these via the context; the context-defining file stays unedited.
 *
 * PLATFORM PRINCIPLE: the resolver is where per-PDA config (vault ref, PDA root,
 * reason digest) enters the cascade — nothing here is hardcoded.
 */
export interface PartnerShredExecutionResolver {
  resolve(input: {
    readonly partner_id: string;
    readonly h_commit: string;
    readonly pda: PartnerPdaRecord;
    readonly escrow: Record<string, unknown>;
    readonly body: ShredRequestBody;
  }): Promise<ShredExecutionRequest> | ShredExecutionRequest;
}

export type PartnerShredRouteContext = PartnerRouteContext & {
  readonly shredExecutor?: ShredExecutor;
  readonly resolveShredRequest?: PartnerShredExecutionResolver;
};

export async function createPartnerShredRequest(
  context: PartnerShredRouteContext,
  partner_id: string,
  h_commit: string,
  body: ShredRequestBody,
): Promise<Record<string, unknown>> {
  const escrow = getPartnerEscrow(context, partner_id, h_commit);
  const pdaId = String(escrow.pda_id);
  const pda = getPartnerPdaRecord(context, { partner_id, key_id: "route", scopes: new Set() }, pdaId);
  // Partner-initiated shred is permitted only when the PDA `shredding_authority`
  // is Joint or Operator. Subject/Timelock/Disabled reject here — `Disabled`
  // PDAs deliberately have no erasure path.
  if (pda.shred_authority !== "Joint" && pda.shred_authority !== "Operator") {
    throw new HttpProblem(
      problemFromCode("AUTH_FORBIDDEN", "partner_shred", {
        detail: "This PDA does not permit partner-initiated shred requests.",
        safe_refs: { partner_id, h_commit, pda_id: pdaId },
      }),
    );
  }

  // Real cascade path: the composition root injected the executor + resolver.
  if (context.shredExecutor && context.resolveShredRequest) {
    const request = await context.resolveShredRequest.resolve({
      partner_id,
      h_commit,
      pda,
      escrow,
      body,
    });
    const result = await runPartnerShredCascade(context.shredExecutor, request, {
      partner_id,
      h_commit,
      pda_id: pdaId,
      shred_authority: pda.shred_authority,
      operational_class: pda.operational_class ?? "b2b_partner",
      request_actor: body.actor_role ?? "partner",
    });
    // Mirror the request into the partner status store so the GET-shred route
    // sees the latest state (parity with the legacy in-memory path).
    context.store.shreds.set(`${partner_id}:${h_commit}`, result);
    return result;
  }

  // Default (no executor wired): in-memory request acknowledgement.
  const status = {
    h_commit,
    partner_id,
    pda_id: pdaId,
    status: "requested",
    request_actor: body.actor_role ?? "partner",
    shred_authority: pda.shred_authority,
    tier_behavior: TIER_BEHAVIOR_MATRIX.shred_request_auth[pda.operational_class ?? "b2b_partner"],
    vault_deletion_status: "pending_on_chain_confirmation",
    blocked_future_reveal: false,
  };
  context.store.shreds.set(`${partner_id}:${h_commit}`, status);
  return status;
}

async function runPartnerShredCascade(
  executor: ShredExecutor,
  request: ShredExecutionRequest,
  refs: {
    partner_id: string;
    h_commit: string;
    pda_id: string;
    shred_authority: string;
    operational_class: "consumer" | "b2b_partner" | "regulated" | "legal_effect";
    request_actor: string;
  },
): Promise<Record<string, unknown>> {
  try {
    const result = await executor.execute(request);
    return {
      h_commit: result.hCommit,
      partner_id: refs.partner_id,
      pda_id: refs.pda_id,
      status: "finalized",
      request_actor: refs.request_actor,
      shred_authority: refs.shred_authority,
      tier_behavior: TIER_BEHAVIOR_MATRIX.shred_request_auth[refs.operational_class],
      vault_deletion_status: "deleted",
      blocked_future_reveal: true,
      shredded_at: result.shreddedAt,
      shares_destroyed: result.sharesDestroyed,
      chain_tx_hash: result.chainTxHash,
      proof_shred: result.proofShred,
    };
  } catch (error) {
    if (error instanceof ShredExecutionError) {
      throw mapPartnerShredExecutionError(error, refs);
    }
    throw error;
  }
}

/** Partner-side `ShredExecutionError` → Problem+JSON (correlation `partner_shred`). */
export function mapPartnerShredExecutionError(
  error: ShredExecutionError,
  refs: { partner_id: string; h_commit: string; pda_id: string },
): HttpProblem {
  const safe_refs = { partner_id: refs.partner_id, h_commit: refs.h_commit, pda_id: refs.pda_id };
  switch (error.context.reasonCode) {
    case "SHRED_AUTHORITY_DISABLED":
      return new HttpProblem(
        problemFromCode("AUTH_FORBIDDEN", "partner_shred", {
          detail: "Shred authority is disabled for this PDA — erasure is not permitted.",
          safe_refs,
        }),
      );
    case "SHRED_BLOCKED_POST_CHALLENGE_REVEAL":
    case "SHRED_BLOCKED_ALREADY_FINALIZED":
      return new HttpProblem(
        problemFromCode("CHAIN_SHRED_FINALIZED", "partner_shred", {
          detail: error.message,
          safe_refs,
        }),
      );
    default:
      return new HttpProblem(
        problemFromCode("VAULT_UNAVAILABLE", "partner_shred", {
          detail: `Crypto-shred cascade failed at step ${error.context.step}: ${error.message}`,
          safe_refs,
          retryable: false,
        }),
      );
  }
}

export function registerCreatePartnerShredRequestRoute(app: FastifyInstance, context: PartnerShredRouteContext): void {
  app.post<{ Params: { h_commit: string }; Body: ShredRequestBody }>(
    "/v1/partners/me/escrows/:h_commit/shred-requests",
    {
      preHandler: context.preHandlers?.("createPartnerShredRequest"),
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
    async (request, reply) => {
      const principal = requirePartnerPrincipal(request);
      return reply
        .code(202)
        .send(await createPartnerShredRequest(context, principal.partner_id, request.params.h_commit, request.body ?? {}));
    },
  );
}
