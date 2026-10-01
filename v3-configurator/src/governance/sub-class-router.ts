import type { SubClass } from "../types/categories.js";

export type GovernanceSurfaceFamily =
  | "schema_library"
  | "fsm_template_library"
  | "oracle_registry"
  | "dsl_version_registry"
  | "wasm_predicate_whitelist"
  | "qtsp_registry"
  | "g4_authority_registry"
  | "cross_field_rules"
  | "default_tables";

export type GovernanceOperation =
  | "addition"
  | "deprecation"
  | "emergency"
  | "constraint_adjustment"
  | "new_rule";

export interface GovernanceRoute {
  readonly sub_class: SubClass;
  readonly authority: string;
  readonly reason: string;
}

export function routeGovernanceChange(
  surface_family: GovernanceSurfaceFamily,
  operation: GovernanceOperation,
): GovernanceRoute {
  if (operation === "emergency") {
    return {
      sub_class: 3,
      authority: "CealisSecurityMultisig plus EmergencyGovernance",
      reason: `${surface_family} emergency path routes through sub-class 3 circuit breaker`,
    };
  }
  if (operation === "addition") {
    return {
      sub_class: 1,
      authority: "TimelockController-7d",
      reason: `${surface_family} addition expands the allowed set without mutating existing entries`,
    };
  }
  if (operation === "deprecation") {
    return {
      sub_class: 2,
      authority: "CealisSecurityMultisig",
      reason: `${surface_family} deprecation removes or refuses an unsafe existing entry`,
    };
  }
  if (operation === "constraint_adjustment") {
    return {
      sub_class: 4,
      authority: "TimelockController-7d",
      reason: `${surface_family} constraint adjustment changes data inside an existing rule shape`,
    };
  }
  return {
    sub_class: 5,
    authority: "RuleAdditionTimelockController plus code-release author-lock",
    reason: `${surface_family} new rule is codepath-bound and requires author-lock review`,
  };
}
