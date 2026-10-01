// M3 (@cealis/v3-custody) facade for @cealis/v3-api.
//
// Purpose: centralize all M3 combiner SDK imports so Codex Phase C
// (combiner-orchestrator + reveal/bundle) doesn't re-import combiner internals
// directly. Phase E verify-sdk does NOT import this facade — it stays
// independent of @cealis/v3-custody per S2-5 §4.7.
//
// Drift guard: if M3 export names drift, this facade fails to compile and the
// foundation test `tests/foundation/m3-import-smoke.test.ts` halts before any
// Codex chunk fires.
//
// Source: v3-custody/src/index.ts (M3 top-level barrel, verified
// 2026-05-11 grep). The barrel re-exports the full combiner surface (15 modules
// in combiner/index.js) via `export *`, plus G2/G3/G4 adapters, plus types,
// plus chain reader, plus refusal helpers, plus redaction.
//
// Expected M3 named symbols (smoke-tested at Phase A foundation test):
//   Adapters: createLitAdapter, createDcipherAdapter, createDrandAdapter,
//             dispatchG3, readG3Choice, G4Phase1Adapter, G4Phase2Adapter,
//             G4Phase, createG4Phase1Adapter, createG4Phase2Adapter
//   Combiner: combineAndDecrypt, runPreVerifyPipeline, decryptAeadPayload,
//             assembleRevealArtifactBundle, jcsCanonicalize, jcsDigest,
//             verifyRegistrySnapshots, verifyGateRecipientPubkeys,
//             orchestrateSigmas, rejectMode3, assertShredStateSignable,
//             verifySupersessionLineage, verifyPluginIntegrity,
//             assertCrossVendorTeeDisjoint, applyRuntimeHardening,
//             reconstructFileKey, dispatchProfile
//   Types:    RefusalCode, REFUSAL_CODES, isBlocking, isAdvisory,
//             isEncryptedReasonMode

// Phase A smoke test reads M3 source-of-truth (v3-custody/src/index.ts)
// and asserts every name in the symbol checklist above is present in the runtime
// export bag.

export * from "@cealis/v3-custody";
