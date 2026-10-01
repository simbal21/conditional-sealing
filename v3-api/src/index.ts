// @cealis/v3-api — public surface (Phase A foundations).
//
// APPEND-ONLY DISCIPLINE — see SPEC-COMPLIANCE-GUARD-M5 §0.
// Codex chunks B/C/D/E append exports below their boundary lines.
// Phase A owns: m-imports facades, types catalog, errors, redaction,
// auth canonical-request, db schema (table-name list only), OpenAPI
// scaffold.

// Phase A — M-facade re-exports for inspection / debug.
export * as M1 from "./m1-imports.js";
export * as M2 from "./m2-imports.js";
export * as M3 from "./m3-imports.js";
export * as M4 from "./m4-imports.js";

// Phase A — typed catalogs (29 operationIds, 18 webhook events, 10 refusal codes,
// 12 error categories, 8 scopes, 15 bundle keys, 12-axis × 4-class tier matrix).
export * from "./types/index.js";

// Phase A — error catalog + Problem+JSON formatter.
export * from "./errors/index.js";

// Phase A — redaction + safe-refs allow-list.
export * from "./redaction/index.js";

// Phase A — HMAC canonical-request signatures (signature only).
export * from "./auth/canonical-request.js";

// Phase A — DB schema (table names + relations; Phase B/C/D fill columns).
export * from "./db/index.js";

// Phase A — OpenAPI scaffold + route registry.
export * from "./openapi/scaffold.js";

// Phase B (ingest + G4 + h_commit + chain-anchor) appends below this line:
export * as HCommit from "./h-commit/index.js";
export * as G4 from "./g4/index.js";
export * from "./chain-anchor/index.js";
export * from "./ingest/index.js";
export * as PhaseBIngestDb from "./db/schema-extensions/ingestions.js";

// Phase C (reveal + combiner-orchestrator + bundle + manifest) appends below:
export * from "./reveal/index.js";
export * from "./combiner-orchestrator/index.js";
export * from "./bundle/index.js";
export * from "./manifest/index.js";
export * from "./db/schema-extensions/reveals.js";

// Phase D (partner + subject + pre-σ + webauthn + auth middleware + webhooks +
// vault + verify route) appends below:
export * from "./auth/index.js";
export * from "./partner/index.js";
export * from "./subject/index.js";
export * from "./pre-sigma/index.js";
export * from "./webauthn/index.js";
export * from "./webhooks/index.js";
export * from "./vault/index.js";
export * from "./verify/index.js";
export * from "./db/schema-extensions/auth.js";

// Resolve star-export name collisions introduced by B/C append-only exports.
export type { G3Choice, G4Phase } from "./types/combiner-manifest.js";
export type { Hex, Hex32, RegistrySnapshotRef } from "./types/reveal-artifact-bundle.js";

// Phase E (cross-surface integration tests; no new public exports in v3-api):
