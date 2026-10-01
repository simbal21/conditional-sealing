// App. I normative types — 11 SCALE / TypeScript structs locked at Phase A.
//
// File-by-type mapping for cross-chunk reference (per M5 lesson 2 —
// later phases import via source path, not embedded names):
//
//   I.1  SdPlan                       → src/types/sd-plan.ts
//   I.2  SdFieldPolicy                → src/types/sd-field-policy.ts
//   I.3  SdClaimConfig                → src/types/sd-claim-config.ts
//   I.4  SdBundle                     → src/types/sd-bundle.ts
//   I.5  SdCleartextItem              → src/types/sd-cleartext-item.ts
//   I.6  SdClaimItem                  → src/types/sd-claim-item.ts
//   I.7  SdFailureItem                → src/types/sd-failure-item.ts
//   I.8  SdMerklePathElement          → src/types/sd-merkle-path.ts
//   I.9  SdProof                      → src/types/sd-proof.ts
//   I.10 SdVerifierRegistryEntry      → src/types/sd-verifier-registry-entry.ts
//   I.11 SdRevocationRecord           → src/types/sd-revocation.ts

export * from "./sd-plan.js";
export * from "./sd-field-policy.js";
export * from "./sd-claim-config.js";
export * from "./sd-bundle.js";
export * from "./sd-cleartext-item.js";
export * from "./sd-claim-item.js";
export * from "./sd-failure-item.js";
export * from "./sd-merkle-path.js";
export * from "./sd-proof.js";
export * from "./sd-verifier-registry-entry.js";
export * from "./sd-revocation.js";
export * from "./predicates.js";
export * from "./composed.js";
export * from "./failure-modes.js";
export * from "./cleartext-opening.js";
