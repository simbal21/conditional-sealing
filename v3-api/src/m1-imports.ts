// M1 (@cealis/v3-crypto) facade for @cealis/v3-api.
//
// Purpose: centralize every M1 import so Codex Phase B/C/D/E never re-imports
// @noble/hashes/curves directly. Mirrors the pattern from M4 (m1-imports.ts).
//
// Drift guard: if M1's export names change, this facade fails to compile and
// the foundation test `tests/foundation/m1-import-smoke.test.ts` halts before
// any Codex chunk fires.
//
// S2-5 surfaces that consume M1:
//   - Ingest (B): commit_AAD, pda_root, AEAD (Mode A plaintext-to-cipher).
//   - Reveal/Bundle (C): JCS, σ verifiers, AEAD-decrypt, recipient stanza MACs.
//   - Auth/Webhook (D): HMAC primitives — webhook signer uses @noble/hashes
//     directly via package dep; M1 facade NOT needed for HMAC.
//   - Verify SDK (E, separate package): σ verifiers, JCS, TAG constants — but
//     verify-sdk imports `@cealis/v3-crypto` directly, NOT this facade.
//
// Expected M1 named symbols (smoke-tested at Phase A foundation test):
//   pda_root:        computePDARoot, buildPDARootPreimage, zeroPDARootInput
//   commit_AAD:      encodeCommitAAD, decodeCommitAAD, computeAADDigest,
//                    validateCommitAAD, CommitAADError, CommitAADValidationError,
//                    ACTIVE_COMMIT_VERSION, COMMIT_AAD_BYTES
//   commit_context:  buildCommitContextPreimage, computeCommitContextDigest,
//                    computeAttestationContextDigest, CommitContextError
//   σ verifiers:     verifySigmaLit, verifySigmaG3, verifySigmaG4,
//                    buildSigmaLitSigningInput, buildSigmaG3DcipherSigningInput,
//                    buildDrandRoundMessage, buildSigmaG4Phase1SigningInput,
//                    G3_CHOICE, G4_PHASE, G4_PHASE1_SIGNING_INPUT_BYTES
//   TAG constants:   TAG_PDA_ROOT_V3, TAG_COMMIT_V3, TAG_AAD_V3,
//                    TAG_AEAD_V3, TAG_G4_ATTESTATION_V3, etc. (30 TAGs total)
//   AEAD:            encryptPayload, decryptPayload, derivePayloadNonce
//   Shamir:          combineShares (or M1's actual name)
//
// `export *` is the only re-export. Single import surface. If M1 deletes a name,
// the foundation smoke test fails on the named import inside.

export * from "@cealis/v3-crypto";

// Type re-exports for type-only consumers (avoids verbatimModuleSyntax issues).
export type {
  Bytes,
  Bytes32,
  PDARootInput,
  CommitAADInput,
  CommitContextInput,
  SigmaLitInput,
  SigmaLitVerifyResult,
  SigmaLitErrorCode,
  SigmaG3Input,
  SigmaG3DcipherInput,
  SigmaG3DrandInput,
  SigmaG3VerifyResult,
  SigmaG3ErrorCode,
  SigmaG4Input,
  SigmaG4Phase1Input,
  SigmaG4Phase2Input,
  SigmaG4VerifyResult,
  SigmaG4ErrorCode,
} from "@cealis/v3-crypto";
