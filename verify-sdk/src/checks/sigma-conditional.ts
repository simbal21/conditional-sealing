import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import { failCheck, passCheck, safeRefsFromBundle, skippedCheck } from "./canonicalization.js";
import { checkSigmaEvidence } from "./sigma-lit.js";

export function checkSigmaConditional(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  const conditional = bundle.sigma_block.sigma_conditional;
  if (conditional === undefined || conditional.length === 0) {
    return skippedCheck("SIGMA_CONDITIONAL.NOT_CONFIGURED", refs);
  }
  for (const evidence of conditional) {
    const check = checkSigmaEvidence("SIGMA_CONDITIONAL", evidence, refs);
    if (check.status !== "pass") return check;
  }
  const indexed = conditional.every((evidence) => evidence.stanza_index === undefined || Number.isInteger(evidence.stanza_index));
  if (!indexed) {
    return failCheck("SIGMA_CONDITIONAL.STANZA_INDEX_MALFORMED", "Conditional sigma stanza_index must be an integer when present.", refs);
  }
  return passCheck("SIGMA_CONDITIONAL.PASS", refs);
}
