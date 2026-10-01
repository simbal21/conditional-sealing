import { describe, it, expect } from "vitest";
import {
  API_SCOPES,
  API_SCOPE_COUNT,
  ROUTE_SCOPE_REQUIREMENTS,
} from "../../src/types/scopes.js";
import { OPERATION_IDS } from "../../src/types/operation-ids.js";

describe("Partner API scopes (S2-5 §5.1 — 8 verbatim)", () => {
  it("locks exactly 8 scopes", () => {
    expect(API_SCOPES.length).toBe(8);
    expect(API_SCOPE_COUNT).toBe(8);
  });

  it("contains all 8 verbatim scope names", () => {
    expect(API_SCOPES).toEqual([
      "pda:read",
      "onboarding_link:create",
      "ingestion:create",
      "escrow:read",
      "reveal:read",
      "webhook:manage",
      "vault:read_partner",
      "verification:read",
    ]);
  });

  it("every operationId with partner_hmac auth has a scope requirement OR is intentionally subject-only", () => {
    // Subject + onboarding + webauthn ops are explicitly NOT scoped via API scopes.
    const SUBJECT_OR_PUBLIC = new Set([
      "createSubjectWebAuthnChallenge",
      "verifySubjectWebAuthn",
      "revokeSubjectSession",
      "listSubjectEscrows",
      "getSubjectEscrowStatus",
      "getSubjectVaultBlob",
      "exportSubjectAuditLog",
      "getSubjectRetention",
      "createSubjectShredRequest",
      "getPreSigmaPayload",
      "submitPreSigmaConfirmations",
      "getVerificationNetworks",
      "getSdkVersions",
    ]);
    for (const id of OPERATION_IDS) {
      if (SUBJECT_OR_PUBLIC.has(id)) continue;
      expect(
        ROUTE_SCOPE_REQUIREMENTS[id],
        `scope requirement missing for partner-auth op: ${id}`,
      ).toBeDefined();
    }
  });
});
