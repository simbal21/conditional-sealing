// Public re-exports for the errors module.
//
// Per the no-touch rules, Phase B-E import error types and helpers
// EXCLUSIVELY through this barrel; nothing under `src/errors/` is
// modified after Phase A.

export type { Stage } from "./stage-codes.js";
export { formatStageCode, parseStageCode, STAGE_CODE_PREFIX, STAGE_VALUES } from "./stage-codes.js";

export type {
  DualFormValidationFailure,
  InternalErrorForm,
  PartnerFacingErrorForm,
} from "./dual-form.js";
