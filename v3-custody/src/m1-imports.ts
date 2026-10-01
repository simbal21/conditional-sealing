// M1 (`@cealis/v3-crypto`) re-export facade.
//
// This is the ONLY entry point through which M3 (`@cealis/v3-custody`)
// consumes M1 byte-exact cryptography. Per SPEC-COMPLIANCE-GUARD-M3 §21,
// Codex chunks B/C/D/E MUST import σ verifiers, Shamir combiner, codecs,
// and TAG_*_V3 constants from this file — they MUST NOT re-implement any
// of these or pull `@noble/curves` / `bls12-381` / `ed25519` directly.
//
// If any name below drifts from M1's actual export name, the foundation
// test `tests/foundation/m1-import-smoke.test.ts` fails LOUDLY at type
// check time AND runtime — surfacing the rename before Codex chunks fire.
//
// Doctrine: σ is authorization, not key material (S2-1 §0.3 LOCKED 2026-05-05).
// σ values may appear in the reveal artifact after verification.
// σ MUST NOT feed any HKDF / be used as Shamir share / be IKM (see §1 of GUARD).

// ============================================================================
// Tags — re-export full TAG_*_V3 + TAG_LABELS + TAG_DIGESTS surface.
// NOTE: we intentionally do NOT use `export * from "@cealis/v3-crypto"` here
// because M1's `AccessStructureProfile` would collide with V3's own typed
// profile in `src/types/access-structure.ts`. Instead we name-list every
// M1 export the SDK consumes (below) — this is more explicit and avoids
// silent re-exports of M1 internals.
// ============================================================================

// TAG_*_V3 constants + tag label/digest tables.
export {
  TAG_LABELS,
  TAG_DIGESTS,
  TAG_COMMIT_V3,
  TAG_AUTHID_V3,
  TAG_SUBJECT_V3,
  TAG_SIGMA_SUBJECT_V3,
  TAG_PDA_ROOT_V3,
  TAG_AAD_V3,
  TAG_AEAD_V3,
  TAG_COMMIT_CONTEXT_V3,
  TAG_ATTESTATION_CONTEXT_V3,
  TAG_LIT_ACC_BINDING_V3,
  TAG_DCIPHER_IBE_BINDING_V3,
  TAG_DRAND_ROUND_BINDING_V3,
  TAG_G3_BINDING_V3,
  TAG_G4_ATTESTATION_V3,
  TAG_G4_ATTESTATION_AUTHORITY_V3,
  TAG_COMPOSITE_IDENTITY_V3,
  TAG_STANZA_MAC_V3,
  TAG_STANZA_WRAP_V3,
  TAG_STANZA_WRAP_NONCE_V3,
  TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
  TAG_REVEAL_CHALLENGE_V3,
  TAG_RECIPIENT_LEAF_V3,
  TAG_P15_ATTESTATION_V3,
  TAG_ARTIFACT_V3,
  TAG_PLUGIN_VERSION_V3,
  TAG_ROTATION_LOG_ANCHOR_V3,
  TAG_CONDITIONAL_RECIPIENTS_POLICY_V3,
  TAG_SUPERSEDED_COMMIT_REGISTRY_V3,
  TAG_ROTATION_AUTHORIZATION_V3,
  TAG_ORACLE_REGISTRY_V3,
} from "@cealis/v3-crypto";
export type { Hex32, TagSymbol } from "@cealis/v3-crypto";

// ============================================================================
// Named re-exports for documentation purposes — these are also covered by the
// `export *` above, but keeping them explicit makes the M1 dependency contract
// scannable. Adapters/combiner consume these by name.
// ============================================================================

// σ verifiers — all four gate σ verification entrypoints + subject σ.
export {
  verifySigmaSubject,
  computeSigmaSubjectInputDigest,
  computeEIP712SubjectDigest,
  SigmaSubjectError,
  SUBJECT_AUTHENTICATOR_CLASS,
  H_COMMIT_PREIMAGE_BYTES,
} from "@cealis/v3-crypto";
export type {
  SigmaSubjectInput,
  SigmaSubjectErrorCode,
  SigmaSubjectDigestInput,
  WebAuthnAssertionInput,
  WebAuthnPlatformSigmaSubjectInput,
  WebAuthnSyncedSigmaSubjectInput,
  EIP712WalletSigmaSubjectInput,
  QESSigmaSubjectInput,
  VerifyResult,
} from "@cealis/v3-crypto";

export {
  verifySigmaLit,
  buildSigmaLitSigningInput,
  SigmaLitError,
} from "@cealis/v3-crypto";
export type {
  SigmaLitInput,
  SigmaLitErrorCode,
  SigmaLitVerifyResult,
} from "@cealis/v3-crypto";

export {
  verifySigmaG3,
  buildSigmaG3DcipherSigningInput,
  buildDrandRoundMessage,
  G3_CHOICE,
  SigmaG3Error,
} from "@cealis/v3-crypto";
export type {
  SigmaG3Input,
  SigmaG3DcipherInput,
  SigmaG3DrandInput,
  SigmaG3ErrorCode,
  SigmaG3VerifyResult,
} from "@cealis/v3-crypto";

export {
  verifySigmaG4,
  buildSigmaG4Phase1SigningInput,
  G4_PHASE,
  G4_PHASE1_SIGNING_INPUT_BYTES,
  SigmaG4Error,
} from "@cealis/v3-crypto";
export type {
  SigmaG4Input,
  SigmaG4Phase1Input,
  SigmaG4Phase2Input,
  SigmaG4ErrorCode,
  SigmaG4VerifyResult,
} from "@cealis/v3-crypto";

// Shamir typed-profile combiner (M1's actual export name is
// `combineDek` plus the `Shamir` namespace). Combiner chunk uses
// `combineDek(records, profile)` — NOT a name like `combineShamir`.
export {
  Shamir,
  combineDek,
  ShamirError,
  ShamirCombinerError,
  GF256_AES_POLYNOMIAL,
} from "@cealis/v3-crypto";
export type {
  AccessStructureProfile as M1AccessStructureProfile,
  ShamirByteShare,
  ShamirCombineResult,
  ShamirErrorCode,
} from "@cealis/v3-crypto";

// Share-record codec (M1 byte layout: 1+1+4+1+32 = 39 bytes).
export {
  encodeShareRecord,
  decodeShareRecord,
  validateShareRecord,
  ShareRecordError,
  ShareRecordValidationError,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_ROLE_LIT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
  SHARE_RECORD_BYTES,
} from "@cealis/v3-crypto";
export type {
  ShareRecord,
  ShareDomain,
  ShareRole,
} from "@cealis/v3-crypto";

// commit_AAD codec — M1's exact names are `encodeCommitAAD`/`decodeCommitAAD`/
// `computeAADDigest` (NOT `computeCommitAad` / `computeCommitAAD`).
export {
  encodeCommitAAD,
  decodeCommitAAD,
  computeAADDigest,
  validateCommitAAD,
  zeroCommitAADInput,
  CommitAADError,
  CommitAADValidationError,
  COMMIT_AAD_BYTES,
  COMMIT_AAD_DIGEST_PREIMAGE_BYTES,
  ACTIVE_COMMIT_VERSION,
} from "@cealis/v3-crypto";
export type {
  CommitAADInput,
  CommitAADErrorCode,
} from "@cealis/v3-crypto";

// PDA root codec — M1's exact name is `computePDARoot` (capital DA).
export {
  computePDARoot,
  buildPDARootPreimage,
  zeroPDARootInput,
} from "@cealis/v3-crypto";
export type { PDARootInput } from "@cealis/v3-crypto";

// commit_context codec.
export {
  computeCommitContextDigest,
  computeAttestationContextDigest,
  buildCommitContextPreimage,
  validateCommitContextInput,
  zeroCommitContextInput,
  CommitContextError,
  CommitContextValidationError,
  COMMIT_CONTEXT_PREIMAGE_BYTES,
  ZERO32,
} from "@cealis/v3-crypto";
export type {
  CommitContextInput,
  CommitContextErrorCode,
} from "@cealis/v3-crypto";

// Stanza MAC + conditional-recipient MAC.
export {
  computeStanzaMac,
  buildStanzaMacInput,
  stanzaMacEquals,
  STANZA_BINDING_TAGS,
} from "@cealis/v3-crypto";

export {
  computeConditionalRecipientMac,
  buildConditionalRecipientMacInput,
  conditionalRecipientMacEquals,
  scaleCompactLengthPrefix,
  ConditionalRecipientMacError,
  ConditionalRecipientMacValidationError,
} from "@cealis/v3-crypto";
export type {
  ConditionalRecipientMacInput,
  ConditionalRecipientMacErrorCode,
} from "@cealis/v3-crypto";

// Age envelope encode/decode/verify — wraps payload AEAD + per-stanza wraps.
export {
  encodeAgeEnvelope,
  materializeAgeEnvelopeStanza,
  decodeAgeEnvelope,
  verifyEnvelope,
  verifyEnvelopeStanzaMacs,
  EnvelopeError,
} from "@cealis/v3-crypto";
export type {
  AgeEnvelopeInput,
  AgeEnvelopeStanzaInput,
  AgeEnvelopeOutput,
  AgeEnvelopeStanza,
  DecodeAgeEnvelopeResult,
  VerifyEnvelopeResult,
  VerifyEnvelopeInput,
  VerifyEnvelopeStanzaContext,
  EnvelopeErrorCode,
  DecodeError,
} from "@cealis/v3-crypto";

// Shared byte aliases.
export type { Bytes, Bytes32 } from "@cealis/v3-crypto";
