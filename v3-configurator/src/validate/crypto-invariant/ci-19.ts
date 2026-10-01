import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { deepStringIncludes, makeCiFailure } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-19")!; // verbatim spec anchor

export function checkCi19(pda: SubmittedPda): DualFormValidationFailure | null {
  const axesMerged =
    pda["reveal_shred_axes_separated"] === false ||
    pda["reveal_terminal_state_implies_shred"] === true ||
    pda["shred_terminal_state_implies_reveal"] === true ||
    deepStringIncludes(pda["template"], [/reveal.*implies.*shred/i, /shred.*implies.*reveal/i]);
  if (!axesMerged) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "reveal_shred_axes_separated",
    code: "REVEAL_SHRED_AXES_MERGED",
    source_field_path: "template",
    failed_predicate: "reveal terminal state never implies shred terminal state, and shred never implies reveal",
    sanitized_value_class: "axis_coupling",
    cross_references: "S2-4 §4.3 CI-19; S2-4 §16.6 hybrid decomposition",
    why_failed:
      "This condition template merges reveal and shred outcomes; Cealis requires the reveal and destruction axes to stay separate.",
    partner_action_text: "Decompose reveal and shred terminal states into independent condition axes.",
  });
}
