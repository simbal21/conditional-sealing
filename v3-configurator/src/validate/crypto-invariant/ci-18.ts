import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { makeCiFailure, stringValue, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-18")!; // verbatim spec anchor

export function checkCi18(pda: SubmittedPda): DualFormValidationFailure | null {
  const lookupMode = stringValue(pda["registry_lookup_mode"]);
  const valid = lookupMode === null || lookupMode === "historical_at_authorization_block";
  if (valid && pda["historical_registry_lookup"] !== false) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "registry_historical_lookup_discipline",
    code: "CURRENT_HEAD_REGISTRY_SUBSTITUTION",
    source_field_path: "registry_lookup_mode",
    failed_predicate: "historical commit verification does not substitute current-head registry state",
    sanitized_value_class: valueClass(lookupMode ?? pda["historical_registry_lookup"]),
    cross_references: "S2-2 §9 registry discipline; S2-4 §10.4 two-layer evaluation; S2-4 §4.3 CI-18",
    why_failed:
      "This template would verify historical commits against current-head registry state instead of the correct historical overlay.",
    partner_action_text: "Use historical_at_authorization_block registry lookup semantics.",
  });
}
