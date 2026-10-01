// @cealis/v3-demo/m3-imports — typed re-export facade for @cealis/v3-custody.
//
// σ-AS-AUTHORIZATION DOCTRINE (LOCKED 2026-05-05) — see PHASE-PLAN §0 drift #3.
// Combiner accepts σ evidence + per-stanza wrapped shares, releases shares
// via per-stanza wrap-decap (σ authorises the decap; σ is NOT key material
// in HKDF), then runs `combineDek` (M1 Shamir) over the released shares to
// reconstruct file_key (= DEK). The high-level composite is
// `combineAndDecrypt`; the byte-exact Shamir step alone is `reconstructFileKey`.
//
// There is NO `combine(shares[]) => FileKey` standalone export; the brief's
// nomenclature is the conceptual contract, the upstream implementation is
// `combineAndDecrypt`. We re-export both APIs and let round code pick the
// right entry point (round 1 + 3 use `combineAndDecrypt`; cross-round
// failure-mode probes may exercise `reconstructFileKey` directly).
//
// HARD GUARD: this file MUST NOT introduce any HKDF-over-σ surface. The
// foundation test `sigma-as-authorization-discipline.test.ts` greps for
// HKDF(σ) / σ-as-IKM patterns across src/ — failure means an upstream
// regression. Surface as INTEGRATION_GAP back-prop to M3.

// ---- High-level combiner (Round 1 + 3 entry point) ----------------------
export {
  combineAndDecrypt,
  reconstructFileKey,
  assembleRevealArtifactBundle as assembleM3RevealArtifactBundle,
  // Pre-verify pipeline (snapshot + endpoint attestation + plugin integrity).
  runPreVerifyPipeline,
  // σ orchestration (admits σ evidence into shares).
  orchestrateSigmas,
} from "@cealis/v3-custody";

export type {
  CombineAndDecryptInput,
} from "@cealis/v3-custody";

// ---- Gate adapters: G2 Lit V3, G3 (drand + dcipher), G4 (Phase 1 + 2) ---
//
// M8 Round 1 + 2 + 2b + 3 uses:
//   - createLitAdapter         (G2 Lit V3)
//   - createDrandAdapter       (G3 drand — per Q-0-1 use-case default for TimeLock)
//   - createG4Phase1Adapter    (G4 Phase 1 — pre-pilot dev scaffold per memory
//                              project_g4_phase_pilot_decision.md)
//
// dcipher and G4 Phase 2 are RE-EXPORTED but unused by M8 demo flows. They
// remain on the surface so cross-round failure-mode injection can route
// through alternative adapters if desired.
//
// dcipher build-time exclusion per M3 PRO-487 / S2-3 §6.2 — runtime usage
// halts on adapter construction; only types are safe to import.
export {
  createLitAdapter,
  createDrandAdapter,
  createDcipherAdapter,
  createG4Phase1Adapter,
  createG4Phase2Adapter,
  G4Phase1Adapter,
  G4Phase2Adapter,
  G4Phase,
  dispatchG3,
  readG3Choice,
} from "@cealis/v3-custody";

export type {
  LitAdapterConfig,
  LitRequestExtras,
  LitPrepareExtras,
  DrandAdapter,
  DrandAdapterConfig,
  DrandRequestExtras,
  DrandPrepareExtras,
  DcipherAdapter,
  DcipherRequestExtras,
  DcipherPrepareExtras,
  G3Adapters,
  G3Choice,
  G3DispatchOperation,
  G3DispatchResult,
  G4Phase1AdapterConfig,
  G4Phase2RequestExtras,
  G4Phase2PrepareExtras,
} from "@cealis/v3-custody";

// ---- Custody types (AccessStructureProfile, SigmaEvidenceBundle, etc.) --
export type {
  AccessStructureProfile,
  CommitRegistrySnapshot,
  AuthorizationRegistrySnapshot,
  DecryptResult,
  SigmaEvidenceBundle,
} from "@cealis/v3-custody";

// ---- Refusal-code helpers (10-code enum runtime guard) ------------------
export * from "@cealis/v3-custody/refusal";

// ---- Custody errors -----------------------------------------------------
export { CustodyError, CUSTODY_ERROR_CODES } from "@cealis/v3-custody";
