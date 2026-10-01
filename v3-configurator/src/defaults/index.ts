export {
  getUseCaseDefaults,
  normalizeDefaultKey,
  USE_CASE_DEFAULTS,
} from "./use-case-index.js";
export type {
  DefaultRecord,
  DefaultValue,
  UseCaseKey,
} from "./use-case-index.js";
export { ARCHETYPE_DEFAULTS, getArchetypeDefaults } from "./archetype-index.js";
export type { ArchetypeKey } from "./archetype-index.js";
export { applyDefaultPrecedence } from "./precedence.js";
export type {
  AppliedDefaultRecord,
  DefaultPrecedenceInput,
  DefaultPrecedenceResult,
} from "./precedence.js";
export {
  assertTemplateBytesUnchanged,
  emitContentAddressedTemplate,
} from "./template-immutability.js";
export type { TemplateEmission } from "./template-immutability.js";
