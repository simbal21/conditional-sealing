// @cealis/v3-demo/m5-imports — typed re-export facade for @cealis/v3-api.
//
// M8 is a CONSUMER of the M5 API surface, not a server. We do NOT re-export
// Fastify route registration helpers — round code talks to the running API
// via HTTP (in-process or in-test against the running server) or to typed
// in-memory adapters where available.
//
// What we re-export:
//   - the typed request/response Schemas + interfaces for ingest
//   - the in-memory IngestionRepository (Phase B round 1 can drive ingest
//     directly without HTTP plumbing for fast CI)
//   - bundle assembly + canonicalization (round code needs to verify the
//     bundle digest matches what M5 produces)
//   - combiner-orchestrator entry points (M5 wraps M3 for event-driven
//     reveal — round 1 + 3 walk through this path)
//   - typed RevealArtifactBundle shape + 15-key catalog
//   - 10-code G4 refusal enum + 18-event webhook taxonomy + 12×4 tier matrix
//   - error catalog + canonical-request signer (M8 may need to sign requests)
//
// NO re-export of: db schema columns, Fastify route handlers, BullMQ workers,
// HTTP server bin.

// ---- M5 typed surface (operationIds, webhook events, refusal codes,
//      tier matrix, bundle keys, scopes) ---------------------------------
export * from "@cealis/v3-api/types";

// ---- Errors (Problem+JSON) ----------------------------------------------
export * from "@cealis/v3-api/errors";

// ---- Ingest (typed request/response + in-memory repository) -------------
// Use the package's named exports — selective list keeps the surface tight.
export {
  createModeAIngestion,
  InMemoryIngestionRepository,
  defaultIngestionRepository,
} from "@cealis/v3-api";
export type {
  ModeAIngestionRequest,
  ModeAIngestionResponse,
  PreflightCommitContext,
  PdaInspectionForIngest,
  IngestionRecord,
  IngestionRepository,
  IngestionDependencies,
  VaultWriter,
  CreateModeAContext,
} from "@cealis/v3-api";

// ---- Reveal: bundle assembly + canonicalization + per-recipient --------
export {
  assembleRevealArtifactBundle,
  bundleStorageRef,
} from "@cealis/v3-api";
export type {
  M3LowLevelBundleScaffold,
  AssembleRevealBundleInput,
  AssembleRevealBundleResult,
} from "@cealis/v3-api";

// ---- Combiner orchestrator (event-driven reveal path) -------------------
export {
  processRevealAuthorizedEvent,
} from "@cealis/v3-api";
export type {
  CombinerEventBus,
  RevealPreconditions,
  EventDrivenRevealInput,
  EventDrivenRevealResult,
} from "@cealis/v3-api";
