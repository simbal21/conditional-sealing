// @cealis/v3-custody — public surface (Phase A foundations).
//
// APPEND-ONLY DISCIPLINE — see SPEC-COMPLIANCE-GUARD-M3 §0.
// Codex chunks B/C/D/E append exports below their boundary lines.
// Phase A owns: m1-imports, types, errors, redaction, refusal, chain,
// adapters interface, access-structure helpers.

// Phase A — M1 re-export facade.
export * from "./m1-imports.js";

// Phase A — typed registry / σ-bundle / access-structure shapes.
export * from "./types/index.js";

// Phase A — operational error catalog (37 codes).
export * from "./errors.js";

// Phase A — abstract adapter interface (Phase B/C/D implement).
export * from "./adapters/index.js";

// Phase A — chain-read SDK (at-commit-block discipline).
export * from "./chain/index.js";

// Phase A — redaction + zeroize + log-sanitize.
export * from "./redaction/index.js";

// Phase A — refusal-code helpers (10-code enum runtime guard).
export * from "./refusal/index.js";

// Phase A — access-structure profile decode helper.
export * from "./access-structure/index.js";

// Phase B (g3-drand + g3-dcipher) appends below this line:
export { createDrandAdapter } from "./g3-drand/index.js";
export type { DrandAdapter, DrandAdapterConfig, DrandRequestExtras, DrandPrepareExtras } from "./g3-drand/index.js";
export { createDcipherAdapter } from "./g3-dcipher/index.js";
export type { DcipherAdapter, DcipherRequestExtras, DcipherPrepareExtras } from "./g3-dcipher/index.js";
export { dispatchG3, readG3Choice } from "./g3-dispatch/index.js";
export type { G3Adapters, G3Choice, G3DispatchOperation, G3DispatchResult } from "./g3-dispatch/index.js";

// Phase C (g2-lit) appends below this line:
export { createLitAdapter } from "./g2-lit/index.js";
export type { LitAdapterConfig, LitRequestExtras, LitPrepareExtras } from "./g2-lit/index.js";

// Phase D (g4-phase1 + g4-phase2 + g4-shared) appends below this line:
export { G4Phase1Adapter } from "./g4-phase1/adapter.js";
export type { G4Phase1AdapterConfig } from "./g4-phase1/adapter.js";
export { G4Phase2Adapter } from "./g4-phase2/adapter.js";
export type { G4Phase2RequestExtras, G4Phase2PrepareExtras } from "./g4-phase2/adapter.js";
export { G4Phase } from "./g4-shared/index.js";

// Post-R2a additions (ecd2d59 + 8010752 + 336ec36) — orchestrator-facing daemon
// transport + refusal-claim verifier so v3-api can consume them as a public surface.
export { MtlsHttpsTransport } from "./g4-phase1/mtls-https-transport.js";
export type { MtlsHttpsTransportConfig } from "./g4-phase1/mtls-https-transport.js";
export {
  verifyRefusalClaim,
  refusalClaimHexToBytes,
  RefusalClaimVerifyError,
} from "./g4-phase1/refusal-claim-verify.js";
export type {
  RefusalClaimVerifyResult,
  RefusalClaimVerifyInput,
  ParsedRefusalClaim,
  RefusalClaimVerifyErrorCode,
} from "./g4-phase1/refusal-claim-verify.js";

import { G4Phase1Adapter, type G4Phase1AdapterConfig } from "./g4-phase1/adapter.js";
import { G4Phase2Adapter } from "./g4-phase2/adapter.js";

export function createG4Phase1Adapter(config: G4Phase1AdapterConfig): G4Phase1Adapter {
  return new G4Phase1Adapter(config);
}

export function createG4Phase2Adapter(): G4Phase2Adapter {
  return new G4Phase2Adapter();
}

// Phase E (combiner + integration) appends below this line:
export * from "./combiner/index.js";
