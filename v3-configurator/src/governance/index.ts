export { routeGovernanceChange } from "./sub-class-router.js";
export type {
  GovernanceOperation,
  GovernanceRoute,
  GovernanceSurfaceFamily,
} from "./sub-class-router.js";
export {
  GOVERNANCE_OPERATIONS,
  GOVERNANCE_SURFACE_FAMILIES,
  getCompositionMatrixRoute,
} from "./composition-matrix.js";
export {
  emitAllGovernanceMetadata,
  emitGovernanceMetadata,
} from "./metadata-emitter.js";
export type { GovernanceMetadataEvent } from "./metadata-emitter.js";
export { routeExtensibilityVector } from "./extensibility-vector-router.js";
export type {
  ExtensibilityVector,
  ExtensibilityVectorRoute,
} from "./extensibility-vector-router.js";
