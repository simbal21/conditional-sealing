// @cealis/v3-configurator — top-level package barrel.
//
// Phase A: types-only surface. Phase E adds emit/verify/diff + CLI
// runtime exports. M5/M8 consumers import from this barrel.

// Errors --------------------------------------------------------------------
export * from "./errors/index.js";

// Types ---------------------------------------------------------------------
export * from "./types/categories.js";
export * from "./types/pda-root.js";
export * from "./types/commit-aad.js";
export * from "./types/ci-codes.js";
export * from "./types/cf-codes.js";
export * from "./types/class-table.js";
export * from "./types/coverage-sidecar.js";
export * from "./types/governance-metadata.js";
export * from "./types/partner-inspection.js";
export * from "./types/audit-trail.js";

// Boundary cascade (signature only — Phase B body) -------------------------
export type {
  BoundaryClassification,
  ClassifySurfaceSignature,
  Surface,
} from "./validate/boundary/types.js";
export { classifySurface } from "./validate/boundary/types.js";

// Redaction (signature only — Phase E body) --------------------------------
export type { RedactSignature, RedactionResult, RedactedValue } from "./redaction/index.js";
export { redact, findPiiMatch, PII_EXCLUSION_PATTERNS } from "./redaction/index.js";

// M-facades (re-export for inspection / debug) -----------------------------
export * as M1 from "./m1-imports.js";
export * as M2 from "./m2-imports.js";
export * as M3 from "./m3-imports.js";

// Phase E runtime surfaces --------------------------------------------------
export * from "./pda/index.js";
export * from "./cli/index.js";
