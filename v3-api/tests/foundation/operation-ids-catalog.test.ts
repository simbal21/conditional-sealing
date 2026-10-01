import { describe, it, expect } from "vitest";
import {
  OPERATION_IDS,
  OPERATION_ID_COUNT,
  OPERATION_TO_PATH,
  type OperationId,
} from "../../src/types/operation-ids.js";

describe("OperationId catalog (S2-5 App. A — 29 verbatim)", () => {
  it("locks exactly 29 operationIds", () => {
    expect(OPERATION_IDS.length).toBe(29);
    expect(OPERATION_ID_COUNT).toBe(29);
  });

  it("contains all expected §2 ingestion ops", () => {
    expect(OPERATION_IDS).toContain("getG4EndpointAttestation");
    expect(OPERATION_IDS).toContain("createModeAIngestion");
    expect(OPERATION_IDS).toContain("getIngestionStatus");
  });

  it("contains all expected §3 reveal ops", () => {
    expect(OPERATION_IDS).toContain("getRevealStatus");
    expect(OPERATION_IDS).toContain("getCombinerManifest");
    expect(OPERATION_IDS).toContain("getRevealArtifactBundle");
  });

  it("contains all expected §5 partner ops (8 total)", () => {
    expect(OPERATION_IDS).toContain("listPartnerPdas");
    expect(OPERATION_IDS).toContain("getPartnerPda");
    expect(OPERATION_IDS).toContain("createOnboardingLink");
    expect(OPERATION_IDS).toContain("getPartnerEscrowStatus");
    expect(OPERATION_IDS).toContain("createPartnerShredRequest");
    expect(OPERATION_IDS).toContain("getPartnerRevealStatus");
    expect(OPERATION_IDS).toContain("getPartnerObligationStatus");
    expect(OPERATION_IDS).toContain("getPartnerShredStatus");
  });

  it("contains all expected §6 subject ops (12 total: 9 self-service + 3 webauthn/session)", () => {
    expect(OPERATION_IDS).toContain("createSubjectWebAuthnChallenge");
    expect(OPERATION_IDS).toContain("verifySubjectWebAuthn");
    expect(OPERATION_IDS).toContain("revokeSubjectSession");
    expect(OPERATION_IDS).toContain("listSubjectEscrows");
    expect(OPERATION_IDS).toContain("getSubjectEscrowStatus");
    expect(OPERATION_IDS).toContain("getSubjectVaultBlob");
    expect(OPERATION_IDS).toContain("exportSubjectAuditLog");
    expect(OPERATION_IDS).toContain("getSubjectRetention");
    expect(OPERATION_IDS).toContain("createSubjectShredRequest");
    expect(OPERATION_IDS).toContain("getPreSigmaPayload");
    expect(OPERATION_IDS).toContain("submitPreSigmaConfirmations");
  });

  it("contains §8 vault + §9 verify ops", () => {
    expect(OPERATION_IDS).toContain("getVaultRetention");
    expect(OPERATION_IDS).toContain("verifyArtifactBundle");
    expect(OPERATION_IDS).toContain("getVerificationNetworks");
    expect(OPERATION_IDS).toContain("getSdkVersions");
  });

  it("every operationId has a path descriptor", () => {
    for (const id of OPERATION_IDS) {
      const desc = OPERATION_TO_PATH[id as OperationId];
      expect(desc, `descriptor missing for ${id}`).toBeDefined();
      expect(desc.path).toMatch(/^\/v1\//);
      expect(["GET", "POST", "DELETE"]).toContain(desc.method);
    }
  });

  it("no duplicate operationIds", () => {
    const seen = new Set(OPERATION_IDS);
    expect(seen.size).toBe(OPERATION_IDS.length);
  });
});
