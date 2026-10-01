import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import { failCheck, isHex, passCheck, safeRefsFromBundle, skippedCheck } from "./canonicalization.js";

export function checkSigmaSubject(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  if (bundle.sigma_block.sigma_subject === undefined) {
    return skippedCheck("SIGMA_SUBJECT.ABSENT", refs);
  }
  if (!isHex(bundle.sigma_block.sigma_subject) || bundle.sigma_block.sigma_subject.length <= 2) {
    return failCheck("SIGMA_SUBJECT.MALFORMED", "sigma_subject must be non-empty hex when present.", refs);
  }
  return passCheck("SIGMA_SUBJECT.PASS", refs);
}
