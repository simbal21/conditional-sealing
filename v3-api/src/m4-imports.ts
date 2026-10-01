// M4 (@cealis/v3-configurator) facade for @cealis/v3-api.
//
// Purpose: centralize all M4 imports — PDA types used by Phase B/C/D/E and by
// Phase D partner PDA-inspection route response shapes (§5.2
// PartnerReadableInspection).
//
// Drift guard: if M4 export names change, this facade fails to compile and
// the foundation test `tests/foundation/m4-import-smoke.test.ts` halts before
// any Codex chunk fires.
//
// Source: v3-configurator/src/index.ts (top-level barrel).
//
// Expected M4 named symbols (smoke-tested):
//   Types: PdaRootFields, PartnerReadableInspection, AuditTrailRecord,
//          Category, TestExitedOn, PDA_ROOT_FIELD_NAMES,
//          AUDIT_TRAIL_FIELD_NAMES, PARTNER_INSPECTION_PRIMITIVE_FIELDS,
//          CATEGORY_VALUES, TEST_EXITED_ON_VALUES
//   Errors: see @cealis/v3-configurator/errors
//
// FIXTURES NOTE (Phase F backprop candidate):
//   M4's package.json declares a `./fixtures` subpath export pointing at
//   `dist/fixtures/app-a/index.js`, but M4's tsconfig.json excludes the
//   `fixtures/` source directory from compilation, so the dist target does
//   not exist. Phase A defers the fixtures import to Phase E integration
//   tests, which use either:
//     (a) a relative file-system path to the on-disk source after M4 is
//         rebuilt with fixtures included, or
//     (b) a Phase F-issued M4 rebuild that produces dist/fixtures/.
//   Phase A locks the type surface here; the Phase E build brief surfaces
//   the fixtures-loading approach with a SOURCE-FILE pointer (no hard-coded
//   function names per M4 lesson 2 / Rule 36).

// Top-level configurator types + errors + emit/CLI surface barrel.
export * from "@cealis/v3-configurator";
