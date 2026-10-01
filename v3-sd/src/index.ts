// @cealis/v3-sd — Cealis V3 Selective Disclosure pipeline (S2-7).
//
// Top-level exports for downstream consumers (M6 Phase E SDK + future M8
// integration). Phase A surfaces:
//
//   - tags             (TAG_SD_*_V3 catalog + byte preimage shapes)
//   - errors           (ERR_SD_* catalog + SdError + safe-refs allow-list)
//   - types            (App. I 11 normative data structures + cleartext-mode
//                      enum + 4+1 predicate types + composed wrapper + §15.2
//                      failure-mode table)
//   - boundary         (asymmetric-isolation type catalog)
//   - mode-b           (assertModeBSdCompatible guard)
//   - setup            (PLONK constraint-budget catalog)
//   - m1-imports       (one-way edge facade for @cealis/v3-crypto)
//   - m2-imports       (M2 ABI facade for DisclosureRegistry + DisclosureRevocationRegistry)
//
// Phase B/C/D/E fill bodies for `commit/`, `merkle/`, `sd-plan/`,
// `cleartext-opening/`, `circuits/`, `prove/`, `onchain/`, etc. Each module's
// own index.ts re-exports for cross-chunk source-pointer discipline (M5
// lesson 2).

export * from "./tags/index.js";
export * from "./errors/index.js";
export * from "./types/index.js";
export * from "./boundary/index.js";
export * from "./mode-b/index.js";
export * from "./setup/index.js";
export * from "./circuits/index.js";
export * from "./prove/index.js";
