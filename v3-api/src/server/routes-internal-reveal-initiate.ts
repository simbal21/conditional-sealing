// POST /internal/reveal/initiate — drives the C3a-closed reveal flow.
//
// PHASE-CLEARANCE DISCIPLINE — the handler MUST:
//   1. mint a `GateClearance<"pre-delivery">` by awaiting clearGatesAt LIVE
//   2. pass it to RevealCoordinatorImpl.persistAndDeliver
//
// There is no way to skip step 1: persistAndDeliver's signature requires the
// pre-delivery clearance and TS rejects any other phase. A snapshot-once
// short-circuit is uninhabitable.
//
// Input contract — minimal request body (this is an internal endpoint):
//   { authorizationId, h_commit, subjectCommitment, partner_id, pda_id }
// matches RevealCoordinatorInput.
//
// Output — 200 + JSON { status, manifest, bundles: [], failed_recipients, [refusal] }
// or 4xx/5xx via Fastify error handler with the RevealCoordinatorError context.

import type { FastifyInstance } from "fastify";

import { clearGatesAt } from "../reveal/reveal-coordinator-impl.js";
import type { RevealCoordinatorImpl } from "../reveal/reveal-coordinator-impl.js";
import type {
  LiveStateReader,
  RevealCoordinatorInput,
  RevealCoordinatorPorts,
  RevealDeliveryQueue,
} from "../reveal/reveal-coordinator.js";
import { RevealCoordinatorError } from "../reveal/reveal-coordinator.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

export interface InternalRevealInitiateDeps {
  readonly revealCoordinator: RevealCoordinatorImpl;
  readonly liveStateReader: LiveStateReader;
  readonly coordinatorPorts: RevealCoordinatorPorts;
  readonly deliveryQueue: RevealDeliveryQueue;
}

export interface InternalRevealInitiateBody {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly subjectCommitment: Hex32;
  readonly partner_id: string;
  readonly pda_id: string;
}

export function registerInternalRevealInitiateRoute(
  app: FastifyInstance,
  deps: InternalRevealInitiateDeps,
): void {
  app.post<{ Body: InternalRevealInitiateBody }>(
    "/internal/reveal/initiate",
    async (request, reply) => {
      const body = request.body;
      if (!isValidHex32(body?.authorizationId)) {
        return reply.code(400).send({
          type: "/problems/request-malformed",
          title: "request-malformed",
          status: 400,
          detail: "authorizationId is required and must be 0x-prefixed 32-byte hex",
          safe_refs: { field: "authorizationId" },
        });
      }
      if (!isValidHex32(body.h_commit)) {
        return reply.code(400).send({
          type: "/problems/request-malformed",
          title: "request-malformed",
          status: 400,
          detail: "h_commit is required and must be 0x-prefixed 32-byte hex",
          safe_refs: { field: "h_commit" },
        });
      }
      if (!isValidHex32(body.subjectCommitment)) {
        return reply.code(400).send({
          type: "/problems/request-malformed",
          title: "request-malformed",
          status: 400,
          detail: "subjectCommitment is required and must be 0x-prefixed 32-byte hex",
          safe_refs: { field: "subjectCommitment" },
        });
      }
      if (typeof body.partner_id !== "string" || body.partner_id.length === 0) {
        return reply.code(400).send({
          type: "/problems/request-malformed",
          title: "request-malformed",
          status: 400,
          detail: "partner_id is required",
          safe_refs: { field: "partner_id" },
        });
      }
      if (typeof body.pda_id !== "string" || body.pda_id.length === 0) {
        return reply.code(400).send({
          type: "/problems/request-malformed",
          title: "request-malformed",
          status: 400,
          detail: "pda_id is required",
          safe_refs: { field: "pda_id" },
        });
      }

      const input: RevealCoordinatorInput = {
        authorizationId: body.authorizationId,
        h_commit: body.h_commit,
        subjectCommitment: body.subjectCommitment,
        partner_id: body.partner_id,
        pda_id: body.pda_id,
      };

      try {
        // ─── Phase-clearance discipline (C3a closure) ───
        //
        // We mint the pre-delivery clearance HERE, IMMEDIATELY before
        // persistAndDeliver. clearGatesAt awaits all 5 live ports in parallel
        // and stamps read_at. The clearance is the only way persistAndDeliver
        // can be called (its type requires GateClearance<"pre-delivery">).
        const clearance = await clearGatesAt("pre-delivery", deps.liveStateReader, {
          authorizationId: input.authorizationId,
          h_commit: input.h_commit,
          subjectCommitment: input.subjectCommitment,
        });

        const result = await deps.revealCoordinator.persistAndDeliver(
          input,
          deps.coordinatorPorts,
          clearance,
          deps.deliveryQueue,
        );

        return reply.code(200).send(result);
      } catch (err) {
        if (err instanceof RevealCoordinatorError) {
          // Reveal-coordinator errors carry pre-declared safe_refs (Rule 47).
          // Map reason code → HTTP status.
          const status = err.context.reasonCode === "REVEAL_DELIVERY_ENQUEUE_FAILED" ? 502 : 409;
          return reply.code(status).send({
            type: "/problems/reveal-blocked",
            title: "reveal-blocked",
            status,
            detail: err.message,
            safe_refs: contextToSafeRefs(err.context),
          });
        }
        const message = err instanceof Error ? err.message : String(err);
        return reply.code(500).send({
          type: "/problems/internal-error",
          title: "internal-error",
          status: 500,
          detail: message,
        });
      }
    },
  );
}

function isValidHex32(value: unknown): value is Hex32 {
  return (
    typeof value === "string" &&
    value.length === 66 &&
    value.startsWith("0x") &&
    /^0x[0-9a-fA-F]{64}$/.test(value)
  );
}

function contextToSafeRefs(
  context: RevealCoordinatorError["context"],
): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(context)) {
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
    }
  }
  return out;
}
