import type {
  ArchetypeTemplate,
  CrossFieldPda,
} from "../validate/cross-field/types.js";
import { hasAcknowledgment } from "../validate/cross-field/helpers.js";

export function routePerPdaOptOut(
  pda: CrossFieldPda,
  archetype_template: ArchetypeTemplate,
): boolean {
  const templatePermits =
    archetype_template.permits_per_pda_mps_opt_out === true ||
    archetype_template.permits_multi_oracle_opt_out === true;
  return templatePermits && hasAcknowledgment(pda, "multi_oracle_opt_out");
}

export function routeClassWideOptOut(): {
  readonly sub_class: 3;
  readonly authority: "CealisSecurityMultisig plus EmergencyGovernance";
} {
  return {
    sub_class: 3,
    authority: "CealisSecurityMultisig plus EmergencyGovernance",
  };
}
