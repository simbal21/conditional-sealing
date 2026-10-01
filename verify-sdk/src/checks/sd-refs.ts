import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import { failCheck, passCheck, safeRefsFromBundle, skippedCheck } from "./canonicalization.js";

export function checkSdRefs(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  const sd = bundle.sd_refs;
  if (sd.status === "not_configured") {
    return skippedCheck("SD_REFS.NOT_CONFIGURED", refs);
  }
  if (sd.status !== "present" && sd.status !== "failed" && sd.status !== "partial_failure") {
    return failCheck("SD_REFS.UNKNOWN_STATUS", "SD refs status is not recognized.", refs);
  }
  if (sd.status === "present" && sd.sdMerkleRoot === undefined && (sd.disclosure_refs?.length ?? 0) === 0) {
    return failCheck("SD_REFS.PRESENT_WITHOUT_REFS", "Present SD refs must carry sdMerkleRoot or disclosure refs.", refs);
  }
  return passCheck("SD_REFS.PASS", refs);
}
