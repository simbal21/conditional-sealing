import type { FastifyInstance, FastifyRequest, preHandlerHookHandler } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import { pickSafeRefs } from "../redaction/safe-refs.js";
import type { OperationId } from "../types/operation-ids.js";
import type { SubjectPrincipal } from "../types/auth.js";
import type { InMemoryPreSigmaConfirmationStore, PreSigmaPayload, PreSigmaSessionBinder } from "../pre-sigma/index.js";
import type { InMemorySubjectSessionStore, InMemoryWebAuthnChallengeStore } from "../webauthn/index.js";

export interface SubjectEscrowRecord {
  readonly user_id: string;
  readonly h_commit: string;
  readonly partner_id: string;
  readonly pda_id: string;
  readonly status: string;
  readonly shred_authority: "Subject" | "Joint" | "Operator" | "Timelock" | "Disabled";
  readonly retention_expires_at: string;
}

export interface SubjectApiStore {
  readonly escrows: Map<string, SubjectEscrowRecord>;
  readonly vaultBlobs: Map<string, Record<string, unknown>>;
  readonly auditRows: Map<string, readonly Record<string, unknown>[]>;
  readonly retention: Map<string, Record<string, unknown>>;
  readonly onboardingPayloads: Map<string, PreSigmaPayload & { onboarding_link_id: string }>;
}

export interface SubjectRouteContext {
  readonly store: SubjectApiStore;
  readonly sessions: InMemorySubjectSessionStore;
  readonly challenges: InMemoryWebAuthnChallengeStore;
  readonly preSigmaBinder: PreSigmaSessionBinder;
  readonly confirmations: InMemoryPreSigmaConfirmationStore;
  readonly preHandlers?: (operationId: OperationId) => preHandlerHookHandler[];
  readonly now?: () => Date;
}

export function createSubjectApiStore(seed?: { readonly user_id?: string; readonly h_commit?: string }): SubjectApiStore {
  const userId = seed?.user_id ?? "subject_demo";
  const hCommit = seed?.h_commit ?? "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const key = `${userId}:${hCommit}`;
  return {
    escrows: new Map([
      [
        key,
        {
          user_id: userId,
          h_commit: hCommit,
          partner_id: "partner_demo",
          pda_id: "pda_demo",
          status: "anchored",
          shred_authority: "Subject",
          retention_expires_at: "2029-01-01T00:00:00.000Z",
        },
      ],
    ]),
    vaultBlobs: new Map([
      [
        key,
        {
          h_commit: hCommit,
          vault_ref: "vault://subject-demo/blob",
          content_type: "application/octet-stream",
          ciphertext_digest: "0x4444444444444444444444444444444444444444444444444444444444444444",
          retention_expires_at: "2029-01-01T00:00:00.000Z",
          shred_state: "active",
          download_url: "https://vault.cealis.local/download/short-lived",
        },
      ],
    ]),
    auditRows: new Map([
      [
        userId,
        [
          {
            event_id: "audit_demo",
            action: "commit.finalized",
            h_commit: hCommit,
            partner_id: "partner_demo",
            pda_id: "pda_demo",
            artifact_digest: "0x5555555555555555555555555555555555555555555555555555555555555555",
          },
        ],
      ],
    ]),
    retention: new Map([
      [
        key,
        {
          h_commit: hCommit,
          retention_policy_id: "obligation_plus_3y",
          retention_expires_at: "2029-01-01T00:00:00.000Z",
          legal_basis_ref: "gdpr_art_6_1_b",
          shred_authority: "Subject",
          shred_condition_summary: "subject_request_with_guardrail",
          vault_access_log_retention: "P12M",
          webhook_metadata_retention: "P90D",
        },
      ],
    ]),
    onboardingPayloads: new Map(),
  };
}

export function listSubjectEscrows(context: SubjectRouteContext, principal: SubjectPrincipal): { escrows: readonly SubjectEscrowRecord[] } {
  return {
    escrows: [...context.store.escrows.values()].filter((record) => record.user_id === principal.user_id),
  };
}

export function registerListSubjectEscrowsRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.get(
    "/v1/subjects/me/escrows",
    { preHandler: context.preHandlers?.("listSubjectEscrows") },
    async (request) => listSubjectEscrows(context, requireSubjectPrincipal(request)),
  );
}

export function requireSubjectPrincipal(request: FastifyRequest): SubjectPrincipal {
  if (!request.subjectPrincipal) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", request.id, {
        detail: "Subject principal missing.",
      }),
    );
  }
  return request.subjectPrincipal;
}

export function getSubjectEscrowRecord(
  context: SubjectRouteContext,
  principal: SubjectPrincipal,
  h_commit: string,
): SubjectEscrowRecord {
  const record = context.store.escrows.get(`${principal.user_id}:${h_commit}`);
  if (!record) {
    throw new HttpProblem(
      problemFromCode("AUTH_FORBIDDEN", "subject_escrow", {
        detail: "Escrow is not visible to this subject session.",
        safe_refs: pickSafeRefs({ h_commit }),
      }),
    );
  }
  return record;
}
