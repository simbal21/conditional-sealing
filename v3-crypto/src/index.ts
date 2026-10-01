// @cealis/v3-crypto — public surface.
//
// IMPORTANT — APPEND-ONLY DISCIPLINE:
// Every Codex chunk (B/C/D/E) appends its exports below. NO chunk may
// delete or rename existing exports without explicit human review. If a
// name conflicts, surface to human. See SPEC-COMPLIANCE-GUARD.md.
//
// Phase A foundations:
export type { Bytes, Bytes32 } from "./types.js";
export * from "./tags.js";
export * from "./codecs/pda-root.js";
export * from "./codecs/share-record.js";
export * from "./envelope/stanza-mac.js";

// Phase B — codecs + σ_subject:
export * from "./codecs/commit-aad.js";
export * from "./codecs/commit-context.js";
export * from "./signatures/sigma-subject.js";

// Phase C — gate σ verifiers:
export * from "./signatures/sigma-lit.js";
export * from "./signatures/sigma-g3.js";
export * from "./signatures/sigma-g4.js";

// Phase D — Shamir typed access-structure combiner:
export * from "./crypto/shamir.js";

// Phase 3 (F-CRYPTO-2) — commit-time DEK dealer (inverse of the §6.3 combiner):
export * from "./crypto/deal-dek.js";

// Phase E — hybrid PQ wrap, payload AEAD, and age envelope:
export * from "./crypto/hybrid-wrap.js";
export * from "./crypto/aead.js";
export * from "./envelope/conditional-recipient-mac.js";
export * from "./envelope/encode.js";
export * from "./envelope/decode.js";
