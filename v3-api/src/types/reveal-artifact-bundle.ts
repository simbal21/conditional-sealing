// RevealArtifactBundle 15-key shape — verbatim from S2-5 §4.1 + App. B.
//
// LOCKED at Phase A. This file is a SECOND canonical copy (mirror of
// `verify-sdk/src/types.ts` App. B verbatim). v3-api keeps its
// own copy to avoid a runtime dependency on verify-sdk (which would break
// the independence pattern in App. B / §9.1).
//
// Drift discipline: Phase A foundation test compares this file's
// REVEAL_ARTIFACT_BUNDLE_TOP_KEYS list against verify-sdk's
// `RevealArtifactBundle` type keys via runtime reflection on a sample bundle.
// If the two drift, the foundation test fails.
//
// Spec source: docs/specs/ingestion-delivery-api-spec.md §4.1 (lines 519-534)
// + App. B (lines 2553-2605).

export type Hex = `0x${string}`;
export type Hex32 = Hex;

export type VerifyStatus = "pass" | "fail" | "skipped";

export type VerifyCheck = {
  status: VerifyStatus;
  code: string;
  message?: string;
  safe_refs?: Record<string, string | number | boolean>;
};

export type RegistrySnapshotRef = {
  registry_name: string;
  chain_id: number;
  registry_address: string;
  checked_block: number;
  checked_block_hash: Hex32;
  entry_digest: Hex32;
  lookup_key?: string;
  proof_ref?: string;
};

export type ChainProofs = {
  chain_id: number;
  condition_engine_address: string;
  reveal_authorized_emitter: string;
  reveal_authorized_event_signature: string;
  reveal_authorized_topics: Hex32[];
  receipt_proof: {
    proof_type: string;
    block_number: number;
    block_hash: Hex32;
    log_index: number;
    proof_nodes?: string[];
  };
  commit_tx_hash: Hex32;
  commit_block: number;
  commit_block_hash: Hex32;
  reveal_authorized_tx_hash: Hex32;
  reveal_authorized_log_index: number;
  reveal_authorized_block: number;
  reveal_authorized_block_hash: Hex32;
  base_finality_confirmations: number;
  finalized_at?: string;
  challenge_window_expired_at?: string;
  condition_module?: string;
  conditionRef?: Hex32;
  shred_registry_state_at_reveal?: string;
};

export type RegistrySnapshots = {
  authorization_block: number;
  authorization_block_hash: Hex32;
  registry_contracts: Record<string, RegistrySnapshotRef>;
  pda_registry?: RegistrySnapshotRef;
  condition_module_registry?: RegistrySnapshotRef;
  gate_authority_registries?: Record<string, RegistrySnapshotRef>;
  shred_registry?: RegistrySnapshotRef;
  issuer_registry?: RegistrySnapshotRef;
  attestor_registry?: RegistrySnapshotRef;
  sd_registry?: RegistrySnapshotRef;
};

export type IssuerAttestationBlock =
  | { status: "not_configured" }
  | {
      status: "present";
      issuer_id: string;
      issuer_registry_ref: RegistrySnapshotRef;
      issuer_signing_key_id: string;
      signature_alg: string;
      signed_payload_digest: Hex32;
      signature: string;
      subject_commitment_v3: Hex32;
      person_key_ref: string;
      valid_from?: string;
      valid_until?: string;
      revocation_ref?: string;
    };

export type FieldProvenanceAttestation = {
  field_path: string;
  field_hash: Hex32;
  attestor_id: string;
  attestor_signing_key_id: string;
  signature_alg: string;
  signed_payload_digest: Hex32;
  signature: string;
  merkle_proof: Hex32[];
  valid_from?: string;
  valid_until?: string;
  revocation_ref?: string;
};

export type ProvenanceBlock =
  | { status: "not_configured" }
  | {
      status: "present";
      p15_attestations_root: Hex32;
      attestor_registry_ref: RegistrySnapshotRef;
      field_attestations: FieldProvenanceAttestation[];
    };

export type ArtifactShredState = {
  h_commit: Hex32;
  shred_state: string;
  proof_shred?: Hex32;
  checked_at_block?: number;
  checked_at_block_hash?: Hex32;
};

export type ArtifactSdRefs = {
  status: "not_configured" | "present" | "failed" | "partial_failure";
  sdMerkleRoot?: string;
  disclosure_refs?: string[];
  revocation_refs?: string[];
};

export type SigmaEvidence = {
  sigma: Hex;
  authority_ref: Hex32;
  variant?: string;
  stanza_index?: number;
  attestation_ref?: Hex32;
  phase?: 1 | 2;
  public_after_reveal: true;
};

export type SigmaBlock = {
  sigma_subject?: Hex;
  sigma_lit: SigmaEvidence;
  sigma_g3: SigmaEvidence;
  sigma_g4: SigmaEvidence;
  sigma_conditional?: SigmaEvidence[];
};

export type RevealArtifactBundle = {
  bundle_version: string;
  canonicalization: {
    format: "JCS";
    rfc: "RFC8785";
    hash: "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))";
  };
  authorization: {
    authorizationId: Hex32;
    h_commit: Hex32;
    commit_version: "0x0302" | string;
    authorization_block: number;
    authorization_block_hash: Hex32;
    authorization_timestamp: string;
    conditionRef: Hex32;
    challenge_window_seconds: number;
    challenge_window_expired_at: string;
    finalized_at: string;
  };
  pda: {
    pda_id: string;
    pda_version: string;
    pda_root: Hex32;
    trust_tier: "tier_a" | "tier_b" | "tier_c";
    operational_class: "consumer" | "b2b_partner" | "regulated" | "legal_effect";
  };
  recipient: {
    recipient_ref: string;
    recipient_pubkey_id?: string;
    schema_selector_digest: Hex32;
  };
  plaintext: {
    schema_selector_digest: Hex32;
    schema_digest: Hex32;
    content_encoding: string;
    fields?: Record<string, unknown>;
    object_ref?: string;
    field_hashes?: Record<string, Hex32>;
  };
  issuer_attestation: IssuerAttestationBlock;
  provenance: ProvenanceBlock;
  sigma_block: SigmaBlock;
  chain_proofs: ChainProofs;
  registry_snapshots: RegistrySnapshots;
  shred_state: ArtifactShredState;
  sd_refs: ArtifactSdRefs;
  verification: {
    artifact_bundle_digest: Hex32;
    verifier_version: string;
    checks?: Record<string, unknown>;
  };
  pii_statement: "recipient_filtered_plaintext_after_valid_reveal";
};

/**
 * Bundle top-level key catalog — Phase A foundation test asserts count = 15.
 * Spec §4.1 lines 519-534 verbatim ordering.
 */
export const REVEAL_ARTIFACT_BUNDLE_TOP_KEYS = [
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
] as const;

export type RevealArtifactBundleTopKey = (typeof REVEAL_ARTIFACT_BUNDLE_TOP_KEYS)[number];

export const REVEAL_ARTIFACT_BUNDLE_TOP_KEY_COUNT: number = REVEAL_ARTIFACT_BUNDLE_TOP_KEYS.length;

/**
 * Bundle version literal — current v1.0 ships under "s2-5.1".
 */
export const BUNDLE_VERSION_CURRENT = "s2-5.1" as const;

/**
 * PII statement literal — §4.1 last key (line 534). Verbatim.
 */
export const PII_STATEMENT_LITERAL =
  "recipient_filtered_plaintext_after_valid_reveal" as const;

/**
 * 15 named SDK verification checks — App. B lines 2636-2652 verbatim.
 * Phase A foundation test asserts count = 15.
 */
export const VERIFY_ARTIFACT_CHECK_NAMES = [
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
] as const;

export type VerifyArtifactCheckName = (typeof VERIFY_ARTIFACT_CHECK_NAMES)[number];
