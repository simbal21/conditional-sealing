// Re-export tombstone primitives from types so callers can `import from
// "@cealis/v3-ops/registry"` without crossing into types layer details.
export { type TombstoneTuple, isValidAtBlock } from "../types/tombstone.js";
