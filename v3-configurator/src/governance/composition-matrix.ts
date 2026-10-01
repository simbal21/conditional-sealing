import type {
  GovernanceOperation,
  GovernanceSurfaceFamily,
} from "./sub-class-router.js";
import {
  routeGovernanceChange,
  type GovernanceRoute,
} from "./sub-class-router.js";

export const GOVERNANCE_SURFACE_FAMILIES: readonly GovernanceSurfaceFamily[] = [
  "schema_library",
  "fsm_template_library",
  "oracle_registry",
  "dsl_version_registry",
  "wasm_predicate_whitelist",
  "qtsp_registry",
  "g4_authority_registry",
  "cross_field_rules",
  "default_tables",
] as const;

export const GOVERNANCE_OPERATIONS: readonly GovernanceOperation[] = [
  "addition",
  "deprecation",
  "emergency",
  "constraint_adjustment",
  "new_rule",
] as const;

export function getCompositionMatrixRoute(
  surface_family: GovernanceSurfaceFamily,
  operation: GovernanceOperation,
): GovernanceRoute {
  return routeGovernanceChange(surface_family, operation);
}
