import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import { failCheck, passCheck, safeRefsFromBundle } from "./canonicalization.js";
import { checkSigmaEvidence } from "./sigma-lit.js";

export function checkSigmaG4(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  const evidence = bundle.sigma_block.sigma_g4;
  const structural = checkSigmaEvidence("SIGMA_G4", evidence, refs);
  if (structural.status !== "pass") return structural;
  if (evidence.phase !== 1 && evidence.phase !== 2) {
    return failCheck("SIGMA_G4.PHASE_MISSING", "sigma_g4 must carry phase 1 or 2.", refs);
  }
  return passCheck("SIGMA_G4.PASS", refs);
}
