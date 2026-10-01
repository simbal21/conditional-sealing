import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest, preHandlerHookHandler } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import type { OperationId } from "../types/operation-ids.js";
import type { PartnerPrincipal } from "../types/auth.js";

export interface PartnerPdaRecord {
  readonly partner_id: string;
  readonly pda_id: string;
  readonly pda_version: string;
  readonly inspection: Record<string, unknown>;
  readonly shred_authority: "Subject" | "Joint" | "Operator" | "Timelock" | "Disabled";
  readonly operational_class?: "consumer" | "b2b_partner" | "regulated" | "legal_effect";
}

export interface PartnerStatusStore {
  readonly pdas: Map<string, PartnerPdaRecord>;
  readonly onboardingLinks: Map<string, Record<string, unknown>>;
  readonly escrows: Map<string, Record<string, unknown>>;
  readonly reveals: Map<string, Record<string, unknown>>;
  readonly obligations: Map<string, Record<string, unknown>>;
  readonly shreds: Map<string, Record<string, unknown>>;
}

export interface PartnerRouteContext {
  readonly store: PartnerStatusStore;
  readonly preHandlers?: (operationId: OperationId) => preHandlerHookHandler[];
  readonly now?: () => Date;
  readonly onboardingBaseUrl?: string;
}

export function createPartnerStatusStore(seed?: {
  readonly partner_id?: string;
  readonly pda_id?: string;
  readonly h_commit?: string;
  readonly authorizationId?: string;
}): PartnerStatusStore {
  const partnerId = seed?.partner_id ?? "partner_demo";
  const pdaId = seed?.pda_id ?? "pda_demo";
  const hCommit = seed?.h_commit ?? "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const authorizationId = seed?.authorizationId ?? "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const pdas = new Map<string, PartnerPdaRecord>();
  pdas.set(`${partnerId}:${pdaId}`, {
    partner_id: partnerId,
    pda_id: pdaId,
    pda_version: "1",
    shred_authority: "Joint",
    operational_class: "b2b_partner",
    inspection: {
      partner_id: partnerId,
      pda_id: pdaId,
      pda_version: "1",
      pda_root: "0x1111111111111111111111111111111111111111111111111111111111111111",
      schema_digest: "0x2222222222222222222222222222222222222222222222222222222222222222",
      condition_module: "PaymentObligation",
      trust_tier: "tier_b",
      operational_class: "b2b_partner",
      g3_choice: "dcipher",
      g4_phase: 2,
      shred_authority: "Joint",
      retention_window: "obligation_plus_3y",
      challenge_windows: { reveal_seconds: 86400, shred_seconds: 86400 },
      validation_status: "valid",
    },
  });
  return {
    pdas,
    onboardingLinks: new Map(),
    escrows: new Map([
      [
        `${partnerId}:${hCommit}`,
        {
          h_commit: hCommit,
          partner_id: partnerId,
          pda_id: pdaId,
          status: "anchored",
          vault_presence: "present",
          retention_expires_at: "2029-01-01T00:00:00.000Z",
          sd_status: "completed",
          chain_anchor_ref: "base-sepolia:commit",
        },
      ],
    ]),
    reveals: new Map([
      [
        `${partnerId}:${authorizationId}`,
        {
          authorizationId,
          h_commit: hCommit,
          partner_id: partnerId,
          pda_id: pdaId,
          status: "finalized",
          artifact_digest: "0x3333333333333333333333333333333333333333333333333333333333333333",
        },
      ],
    ]),
    obligations: new Map([
      [
        `${partnerId}:obl_demo`,
        {
          obligationId: "obl_demo",
          partner_id: partnerId,
          pda_id: pdaId,
          status: "active",
          condition_module: "PaymentObligation",
        },
      ],
    ]),
    shreds: new Map([
      [
        `${partnerId}:${hCommit}`,
        {
          h_commit: hCommit,
          partner_id: partnerId,
          pda_id: pdaId,
          status: "not_requested",
          vault_deletion_status: "not_started",
          blocked_future_reveal: false,
        },
      ],
    ]),
  };
}

export function listPartnerPdas(context: PartnerRouteContext, principal: PartnerPrincipal): { pdas: Record<string, unknown>[] } {
  return {
    pdas: [...context.store.pdas.values()]
      .filter((record) => record.partner_id === principal.partner_id)
      .map((record) => record.inspection),
  };
}

export function registerListPartnerPdasRoute(app: FastifyInstance, context: PartnerRouteContext): void {
  app.get(
    "/v1/partners/me/pdas",
    { preHandler: context.preHandlers?.("listPartnerPdas") },
    async (request) => listPartnerPdas(context, requirePartnerPrincipal(request)),
  );
}

export function requirePartnerPrincipal(request: FastifyRequest): PartnerPrincipal {
  if (!request.partnerPrincipal) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", request.id, {
        detail: "Partner principal missing.",
      }),
    );
  }
  return request.partnerPrincipal;
}

export function getPartnerPdaRecord(
  context: PartnerRouteContext,
  principal: PartnerPrincipal,
  pdaId: string,
): PartnerPdaRecord {
  const record = context.store.pdas.get(`${principal.partner_id}:${pdaId}`);
  if (!record) {
    throw new HttpProblem(
      problemFromCode("AUTH_FORBIDDEN", "partner", {
        detail: "PDA is not visible to this partner.",
        safe_refs: { partner_id: principal.partner_id, pda_id: pdaId },
      }),
    );
  }
  return record;
}

export function newOnboardingId(): string {
  return randomUUID();
}
