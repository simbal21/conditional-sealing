// @cealis/verify-sdk public types — verbatim from
// docs/specs/ingestion-delivery-api-spec.md App. B (lines 2431-2730).
//
// LOCKED at Phase A. Phase E implements function bodies; Phase E MUST NOT
// alter the shapes below. Drift caught at Phase A foundation test.
//
// SECURITY-AUDIT-2026-05-14 amendment: VerifyArtifactOptions extended with
// OPTIONAL `maxArtifactAgeSeconds` (TS-API-F-03). Additive, backward-compatible.
// Spec App. B should add the field in the next backprop cycle.

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

export type VerifyArtifactOptions = {
  chainRpcUrl?: string;
  registryOverrides?: Record<string, string>;
  requireOnlineRegistryChecks?: boolean;
  now?: Date;
  expectedRecipientRef?: string;
  /**
   * Max age (in seconds) of `bundle.authorization.finalized_at` accepted by
   * `verifyArtifactBundle`. When set, bundles older than this window FAIL
   * verification — blocks artifact-replay attacks where a captured legitimate
   * bundle is reused months later.
   *
   * **R2b-3 TS-API-F-03 (2026-05-21) — freshness is DEFAULT-ON.** When
   * undefined, the freshness check enforces a **24-hour (86_400s)** window
   * automatically — the caller no longer needs to "enforce freshness out of
   * band." Closes the opt-in trust-by-default defect that let captured
   * legitimate bundles replay indefinitely against verify-sdk callers who
   * forgot the option. Override with a tighter window (e.g. 3_600s for
   * near-real-time use cases) by setting this field.
   *
   * To genuinely skip the freshness check — only legitimate for archival
   * replay or audit verification of historical bundles — set
   * `disableFreshnessCheck: true` explicitly. Omitting the option without
   * setting the disable flag NO LONGER skips the check.
   *
   * Security-audit-2026-05-14 TS-API-F-03.
   */
  maxArtifactAgeSeconds?: number;
  /**
   * Explicit opt-OUT for the freshness check (R2b-3 TS-API-F-03 closure).
   * MUST be explicitly set to `true` to skip; omitting the field or setting
   * `false` runs the check at the default (or caller-provided) window.
   * Type-discriminated + audit-greppable — silent skip is no longer possible.
   *
   * Legitimate use cases: archival audit replay of historical bundles, batch
   * compliance verification, evidence-preservation workflows where the bundle
   * is intentionally older than any reasonable freshness window. Production
   * webhook-style consumers SHOULD NOT set this.
   */
  disableFreshnessCheck?: boolean;
};

export type VerifyArtifactResult = {
  overall: VerifyStatus;
  artifact_bundle_digest: Hex32;
  checks: {
    canonicalization: VerifyCheck;
    chainProof: VerifyCheck;
    pdaRoot: VerifyCheck;
    registrySnapshots: VerifyCheck;
    endpointAttestation: VerifyCheck;
    issuerAttestation: VerifyCheck;
    provenance: VerifyCheck;
    sigmaSubject: VerifyCheck;
    sigmaLit: VerifyCheck;
    sigmaG3: VerifyCheck;
    sigmaG4: VerifyCheck;
    sigmaConditional: VerifyCheck;
    shredState: VerifyCheck;
    recipientSelector: VerifyCheck;
    sdRefs: VerifyCheck;
    /** Artifact-bundle freshness check (security-audit-2026-05-14 TS-API-F-03). */
    freshness: VerifyCheck;
  };
  safe_refs: {
    authorizationId: Hex32;
    h_commit: Hex32;
    pda_root?: Hex32;
    authorization_block?: number;
  };
};

export type SdOutput = {
  status: "complete" | "failed" | "partial_failure" | "skipped" | "not_configured";
  authorizationId?: Hex32;
  h_commit?: Hex32;
  pda_root?: Hex32;
  partner_id?: string;
  pda_id?: string;
  schema_digest?: Hex32;
  sdMerkleRoot?: string;
  sd_plan_digest?: Hex32;
  cleartext?: unknown[];
  claims?: unknown[];
  failures?: unknown[];
};

export type VerifySdOptions = {
  checkExpiry?: boolean;
  checkRevocation?: boolean;
  now?: Date;
};

export type VerifySdResult = {
  overall: VerifyStatus;
  checks: Record<string, VerifyCheck>;
};

export type WebhookHeaders = {
  "x-cealis-signature": string;
  "x-cealis-timestamp": string;
  "x-cealis-event": string;
  "x-cealis-delivery": string;
};

export type WebhookVerificationResult = {
  overall: VerifyStatus;
  event_id?: string;
  event_type?: string;
  checks: {
    timestamp: VerifyCheck;
    signature: VerifyCheck;
    replayWindow: VerifyCheck;
  };
};

// Locked names of the 15 named checks (App. B lines 2636-2652). Phase A foundation
// test asserts this constant length is exactly 15.
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
  // Security-audit-2026-05-14 TS-API-F-03: freshness check added to block
  // artifact-replay attacks. Defaults to `skipped` unless caller sets
  // maxArtifactAgeSeconds; partner SDKs should opt in.
  "freshness",
] as const;

export type VerifyArtifactCheckName = (typeof VERIFY_ARTIFACT_CHECK_NAMES)[number];

// ---- Refusal verification surface (internal integration-gap close, 2026-05-14) ----
//
// Closes an internal integration-gap item. The verify-sdk MUST stay independent of
// @cealis/v3-api (S2-5 §4.7 + §9.1 normative independence). Therefore the
// refusal-entry shape is declared STRUCTURALLY here — TypeScript structural
// typing makes any v3-api `G4RefusalEntry` assignment-compatible without
// importing it, preserving offline-independence.
//
// Field layout mirrors @cealis/v3-api `G4RefusalEntry` (combiner-orchestrator/
// refusal-handler.ts) so recipients can pass the upstream type directly.

export type RefusalReasonVisibility = "encrypted" | "plaintext";

/**
 * Structural shape of a G4 refusal entry as delivered to recipients
 * (verbatim field set from S2-5 §10.4 + S2-2 §14).
 *
 * Receiver-side ergonomics: callers may pass `@cealis/v3-api`'s
 * `G4RefusalEntry` directly — its field set is identical to this shape, so
 * structural-typing accepts it without cast or import.
 */
export type RefusalEntryShape = {
  refusal_id: string;
  authorization_id: Hex32;
  h_commit: Hex32;
  partner_id: string;
  pda_id: string;
  reason_code: number;
  reason_code_hex: string;
  reason_label: string;
  reason_visibility: RefusalReasonVisibility;
  encrypted_reason_ref?: string;
  refused_at: string;
  blocking: boolean;
};

/**
 * Input to `verifyRefusalArtifact`. The webhook triple is the HMAC-signed
 * delivery surface per S2-5 §3.6; `refusalEntry` is the structural payload.
 */
export type VerifyRefusalArtifactInput = {
  webhookHeaders: WebhookHeaders;
  webhookBody: Uint8Array;
  webhookSecret: Uint8Array;
  refusalEntry: RefusalEntryShape;
  now?: Date;
};

/**
 * Result of `verifyRefusalArtifact`. The brief shape
 * `{verified, kind, reasonCode}` is preserved; additional fields surface
 * the composed webhook check + the encrypted-reason / blocking discriminators
 * so recipients have one verifier, not two.
 */
export type VerifyRefusalArtifactResult = {
  verified: boolean;
  kind: "refusal";
  reasonCode: number;
  reasonLabel: string;
  reasonVisibility: RefusalReasonVisibility;
  encryptedReasonRef?: string;
  blocking: boolean;
  checks: {
    webhook: WebhookVerificationResult;
    eventType: VerifyCheck;
    reasonCode: VerifyCheck;
    encryptedReason: VerifyCheck;
    visibilityConsistency: VerifyCheck;
    blockingConsistency: VerifyCheck;
    reasonCodeHex: VerifyCheck;
  };
};

/**
 * Refusal reason-code range per S2-5 §10.4 (0x01..0x0A inclusive).
 * 0x01..0x09 are BLOCKING; 0x0A is ADVISORY.
 */
export const REFUSAL_REASON_CODE_MIN = 0x01;
export const REFUSAL_REASON_CODE_MAX = 0x0a;
export const REFUSAL_BLOCKING_MAX = 0x09;
export const REFUSAL_ENCRYPTED_REASON_CODES = [0x02, 0x03] as const;
