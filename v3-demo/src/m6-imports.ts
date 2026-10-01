// @cealis/v3-demo/m6-imports — typed re-export facade for @cealis/v3-sd.
//
// USED ONLY BY ROUND 3 + Phase E cross-round (7-stage isolation table +
// Mode B defense-in-depth). Round 1, 2, 2b do not import this facade.
//
// SD pipeline is asymmetrically isolated from escrow per S2-7 §15.2 —
// see PHASE-PLAN §3 Phase E. The 7 inject points map to specific error
// codes in @cealis/v3-sd's ERR_SD_* catalog.
//
// PLONK setup: M6 ships circuit-metadata + verifier-ref derivation; actual
// prove/verify happens at round runtime against locally-held vkeys.

// ---- Tags + errors + types catalog --------------------------------------
export * from "@cealis/v3-sd/tags";
export * from "@cealis/v3-sd/errors";
export * from "@cealis/v3-sd/types";

// ---- Mode B compatibility guard (defense-in-depth M6 side) --------------
// `assertModeBSdCompatible` is the M6 independent rejection per S2-7 §14.2.
// Phase E Cross-Round invokes this directly to verify defense-in-depth.
// Re-exported via the package barrel.
export * from "@cealis/v3-sd";

// ---- Producer-side SD Merkle tree + scalar encoding (Round 3 real bundle) -
// The §5.1 producer leaf/tree functions + BN254 scalar (de)serialization, used
// to emit a REAL single-field SD tree whose field_commitment / merkle_path /
// sdMerkleRoot the partner-SDK verifier (verify-cleartext-field) recomputes.
// Explicit named re-exports (not `export *`) to avoid barrel name ambiguity.
export { buildBinaryPoseidonTree, type SdMerkleLeafInput } from "@cealis/v3-sd/merkle";
export { scalarHex, scalarFromBytesMod, bytesFromHex } from "@cealis/v3-sd/encoding";

// NOTE: The @cealis/v3-sd-verify (partner verification SDK) package is
// re-exported separately by m6-sdk-imports.ts to keep the M6-pipeline
// surface distinct from the M6-partner-verify surface (S2-7 §9 + §15).
