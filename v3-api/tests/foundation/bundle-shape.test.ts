import { describe, it, expect } from "vitest";
import {
  REVEAL_ARTIFACT_BUNDLE_TOP_KEYS,
  REVEAL_ARTIFACT_BUNDLE_TOP_KEY_COUNT,
  VERIFY_ARTIFACT_CHECK_NAMES,
  BUNDLE_VERSION_CURRENT,
  PII_STATEMENT_LITERAL,
} from "../../src/types/reveal-artifact-bundle.js";
import {
  COMBINER_MANIFEST_REQUIRED_FIELDS,
  COMBINER_MANIFEST_REQUIRED_FIELD_COUNT,
} from "../../src/types/combiner-manifest.js";

describe("RevealArtifactBundle shape (S2-5 §4.1 + App. B — 15 keys verbatim)", () => {
  it("locks exactly 15 top-level keys", () => {
    expect(REVEAL_ARTIFACT_BUNDLE_TOP_KEYS.length).toBe(15);
    expect(REVEAL_ARTIFACT_BUNDLE_TOP_KEY_COUNT).toBe(15);
  });

  it("contains all 15 verbatim top-level keys in order", () => {
    expect(REVEAL_ARTIFACT_BUNDLE_TOP_KEYS).toEqual([
      "bundle_version",
      "canonicalization",
      "authorization",
      "pda",
      "recipient",
      "plaintext",
      "issuer_attestation",
      "provenance",
      "sigma_block",
      "chain_proofs",
      "registry_snapshots",
      "shred_state",
      "sd_refs",
      "verification",
      "pii_statement",
    ]);
  });

  it("bundle version constant is 's2-5.1'", () => {
    expect(BUNDLE_VERSION_CURRENT).toBe("s2-5.1");
  });

  it("PII statement literal verbatim from §4.1", () => {
    expect(PII_STATEMENT_LITERAL).toBe("recipient_filtered_plaintext_after_valid_reveal");
  });
});

describe("SDK verify result (App. B lines 2636-2652 — 15 named checks)", () => {
  it("locks exactly 15 named checks", () => {
    expect(VERIFY_ARTIFACT_CHECK_NAMES.length).toBe(15);
  });

  it("contains all 15 verbatim check names", () => {
    expect(VERIFY_ARTIFACT_CHECK_NAMES).toEqual([
      "canonicalization",
      "chainProof",
      "pdaRoot",
      "registrySnapshots",
      "endpointAttestation",
      "issuerAttestation",
      "provenance",
      "sigmaSubject",
      "sigmaLit",
      "sigmaG3",
      "sigmaG4",
      "sigmaConditional",
      "shredState",
      "recipientSelector",
      "sdRefs",
    ]);
  });
});

describe("CombinerManifest required fields (S2-5 App. A — 16 verbatim)", () => {
  it("locks exactly 16 required fields", () => {
    expect(COMBINER_MANIFEST_REQUIRED_FIELDS.length).toBe(16);
    expect(COMBINER_MANIFEST_REQUIRED_FIELD_COUNT).toBe(16);
  });

  it("contains all 16 verbatim required fields", () => {
    expect(COMBINER_MANIFEST_REQUIRED_FIELDS).toEqual([
      "authorizationId",
      "h_commit",
      "authorization_block",
      "block_hash",
      "pda_id",
      "g3_choice",
      "g4_phase",
      "gate_endpoints",
      "registry_snapshot_refs",
      "recipient_policy",
      "combiner_execution_context",
      "delegation_allowed",
      "recipient_control_requirement",
      "tee_hsm_required",
      "risk_statement_required",
      "policy_evidence_refs",
    ]);
  });
});
