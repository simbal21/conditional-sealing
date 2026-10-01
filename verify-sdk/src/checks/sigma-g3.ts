import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import { safeRefsFromBundle } from "./canonicalization.js";
import { checkSigmaEvidence } from "./sigma-lit.js";

export function checkSigmaG3(bundle: RevealArtifactBundle): VerifyCheck {
  return checkSigmaEvidence("SIGMA_G3", bundle.sigma_block.sigma_g3, safeRefsFromBundle(bundle));
}
