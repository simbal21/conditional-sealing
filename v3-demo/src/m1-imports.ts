// @cealis/v3-demo/m1-imports — typed re-export facade for @cealis/v3-crypto.
//
// NO RE-AUTHORING. Every symbol re-exported here is verified to exist in
// @cealis/v3-crypto's `src/index.ts` barrel at Phase A authoring time.
// If an upstream change retires a symbol, this file fails typecheck —
// the resulting drift is surfaced in the internal integration-gap log for back-prop to M0+M1
// (per Rule 36 + integration-gap discipline).
//
// Brief → upstream name mapping (advisor 2026-05-14):
//   "SealedCommit"   → does NOT exist as a single type. M1 exposes
//                      CommitAADInput + computeAADDigest + decodeCommitAAD.
//                      Round code that wants a "commit blob" composes these.
//   "FileKey"        → just `Uint8Array` (no named alias upstream).
//   "Shamir.combine" → `combineDek(records, profile)` lives on the crypto
//                      surface; the custody combiner wraps it (see m3-imports).
//   "age-plugin envelope decoder" → `decodeAgeEnvelope`, `verifyEnvelope`,
//                                   `verifyEnvelopeStanzaMacs`.
//   "AEAD primitives" → `encryptPayload` + `decryptPayload`.
//   "All TAG_*_V3 constants" → re-export TAG_DIGESTS map + named constants
//                              via the barrel `export *`.
//
// Phase B/C/D consumers import from THIS file, never from @cealis/v3-crypto
// directly. Centralising the surface here ensures one upgrade point if M0+M1
// rev'd.

// ---- TAG catalog --------------------------------------------------------
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
export type { TagSymbol, Hex32 } from "@cealis/v3-crypto";

// ---- Commit AAD (the closest thing to a "SealedCommit") -----------------
export {
  COMMIT_AAD_BYTES,
  ACTIVE_COMMIT_VERSION,
  validateCommitAAD,
  encodeCommitAAD,
  decodeCommitAAD,
  computeAADDigest,
  zeroCommitAADInput,
  CommitAADValidationError,
  CommitAADError,
} from "@cealis/v3-crypto";
export type { CommitAADInput, CommitAADErrorCode } from "@cealis/v3-crypto";

// ---- PDA root -----------------------------------------------------------
export {
  buildPDARootPreimage,
  computePDARoot,
  zeroPDARootInput,
} from "@cealis/v3-crypto";
export type { PDARootInput } from "@cealis/v3-crypto";

// ---- ShareRecord codec (Shamir typed access-structure input) ------------
export {
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_ROLE_LIT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
} from "@cealis/v3-crypto";
export type { ShareDomain, ShareRole } from "@cealis/v3-crypto";

// ---- Shamir typed combiner (combineDek = σ-as-authorization step 2) -----
// NOTE: this is the BYTE-EXACT combiner. The high-level σ-as-authorization
// composite (σ → share → Shamir → AEAD) lives in @cealis/v3-custody as
// `combineAndDecrypt` — see m3-imports.ts. NO HKDF over σ values anywhere
// in either surface (σ-as-IKM is a retired predecessor framing).
export { combineDek, Shamir, ShamirCombinerError, ShamirError } from "@cealis/v3-crypto";
export type {
  AccessStructureProfile,
  ShamirCombineResult,
  ShamirByteShare,
  ShamirErrorCode,
} from "@cealis/v3-crypto";

// ---- σ_subject + σ_lit + σ_g3 + σ_g4 verifiers --------------------------
export {
  SUBJECT_AUTHENTICATOR_CLASS,
  H_COMMIT_PREIMAGE_BYTES,
  SigmaSubjectError,
  computeSigmaSubjectInputDigest,
  computeEIP712SubjectDigest,
  verifySigmaSubject,
} from "@cealis/v3-crypto";
export type {
  SigmaSubjectInput,
  SigmaSubjectDigestInput,
  WebAuthnAssertionInput,
  WebAuthnPlatformSigmaSubjectInput,
  WebAuthnSyncedSigmaSubjectInput,
  EIP712WalletSigmaSubjectInput,
  QESSigmaSubjectInput,
  SigmaSubjectErrorCode,
} from "@cealis/v3-crypto";

export {
  SigmaLitError,
  buildSigmaLitSigningInput,
  verifySigmaLit,
} from "@cealis/v3-crypto";
export type { SigmaLitInput, SigmaLitErrorCode, SigmaLitVerifyResult } from "@cealis/v3-crypto";

export {
  G3_CHOICE,
  SigmaG3Error,
  buildSigmaG3DcipherSigningInput,
  buildDrandRoundMessage,
  verifySigmaG3,
} from "@cealis/v3-crypto";
export type {
  SigmaG3Input,
  SigmaG3DcipherInput,
  SigmaG3DrandInput,
  SigmaG3ErrorCode,
  SigmaG3VerifyResult,
} from "@cealis/v3-crypto";

export {
  G4_PHASE,
  G4_PHASE1_SIGNING_INPUT_BYTES,
  SigmaG4Error,
  buildSigmaG4Phase1SigningInput,
  verifySigmaG4,
} from "@cealis/v3-crypto";
export type {
  SigmaG4Input,
  SigmaG4Phase1Input,
  SigmaG4Phase2Input,
  SigmaG4ErrorCode,
  SigmaG4VerifyResult,
} from "@cealis/v3-crypto";

// ---- Payload AEAD (DEK-based content encryption) ------------------------
export {
  derivePayloadNonce,
  encryptPayload,
  decryptPayload,
  PayloadAEADError,
  PayloadAEADValidationError,
} from "@cealis/v3-crypto";
export type {
  PayloadAEADBaseInput,
  EncryptPayloadInput,
  DecryptPayloadInput,
  EncryptPayloadOutput,
  DecryptPayloadResult,
  PayloadAEADErrorCode,
} from "@cealis/v3-crypto";

// ---- Hybrid PQ wrap (per-stanza, σ-as-authorization unlocks decap) ------
export {
  ML_KEM_768_PUBLIC_KEY_BYTES,
  ML_KEM_768_SECRET_KEY_BYTES,
  ML_KEM_768_CIPHERTEXT_BYTES,
  X25519_KEY_BYTES,
  WRAPPED_SHARE_PLAINTEXT_BYTES,
  WRAPPED_SHARE_BYTES,
  HYBRID_WRAP_PAYLOAD_BYTES,
  HYBRID_WRAP_AAD_BYTES,
  HybridWrapError,
  HybridWrapValidationError,
  encodeHybridWrapAAD,
  encodeWrappedStanzaPayload,
  decodeWrappedStanzaPayload,
  deriveStanzaWrapKey,
  deriveStanzaWrapNonce,
  wrapShareForRecipient,
  unwrapShareForRecipient,
} from "@cealis/v3-crypto";
export type {
  HybridWrapAADFields,
  WrappedStanza,
  HybridWrapRecipientPublicKeys,
  HybridWrapRecipientPrivateKeys,
  WrapShareForRecipientInput,
  UnwrapShareForRecipientInput,
  HybridWrapErrorCode,
  HybridUnwrapResult,
} from "@cealis/v3-crypto";

// ---- age-plugin envelope encode / decode + stanza MAC -------------------
export {
  STANZA_BINDING_TAGS,
  buildStanzaMacInput,
  computeStanzaMac,
  stanzaMacEquals,
} from "@cealis/v3-crypto";

export {
  decodeAgeEnvelope,
  verifyEnvelope,
  verifyEnvelopeStanzaMacs,
  EnvelopeError,
} from "@cealis/v3-crypto";
export type {
  AgeEnvelopeOutput,
  AgeEnvelopeStanza,
  DecodeAgeEnvelopeResult,
  VerifyEnvelopeResult,
  VerifyEnvelopeInput,
  VerifyEnvelopeStanzaContext,
  DecodeError,
  EnvelopeErrorCode,
} from "@cealis/v3-crypto";

export { materializeAgeEnvelopeStanza, encodeAgeEnvelope } from "@cealis/v3-crypto";
export type { AgeEnvelopeStanzaInput, AgeEnvelopeInput } from "@cealis/v3-crypto";

// ---- Bytes alias ---------------------------------------------------------
export type { Bytes, Bytes32 } from "@cealis/v3-crypto";
