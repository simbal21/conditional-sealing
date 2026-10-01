export type ExtensibilityVector =
  | "template_composition"
  | "oracle_onboarding"
  | "dsl_wasm_extension";

export interface ExtensibilityVectorRoute {
  readonly vector: ExtensibilityVector;
  readonly priority: 1 | 2 | 3;
  readonly default_governance_path: string;
  readonly commit_version_coordination_risk: boolean;
}

export function routeExtensibilityVector(
  vector: ExtensibilityVector,
): ExtensibilityVectorRoute {
  if (vector === "template_composition") {
    return {
      vector,
      priority: 1,
      default_governance_path:
        "sub-class 1 addition; sub-class 2 deprecation for unsafe old templates",
      commit_version_coordination_risk: false,
    };
  }
  if (vector === "oracle_onboarding") {
    return {
      vector,
      priority: 2,
      default_governance_path:
        "7-day timelocked addition with vetting; sub-class 2/3 deprecation by severity",
      commit_version_coordination_risk: false,
    };
  }
  return {
    vector,
    priority: 3,
    default_governance_path:
      "design review, predicate registration, audit, S2-6 rollout ceremony, author-lock check",
    commit_version_coordination_risk: true,
  };
}
