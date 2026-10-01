import type { RevealArtifactBundle, SigmaEvidence, VerifyCheck } from "../types.js";
import { failCheck, isHex, isHex32, passCheck, safeRefsFromBundle } from "./canonicalization.js";

export function checkSigmaLit(bundle: RevealArtifactBundle): VerifyCheck {
  return checkSigmaEvidence("SIGMA_LIT", bundle.sigma_block.sigma_lit, safeRefsFromBundle(bundle));
}

export function checkSigmaEvidence(
  codePrefix: string,
  evidence: SigmaEvidence,
  safeRefs: Record<string, unknown>,
): VerifyCheck {
  if (!isHex(evidence.sigma) || evidence.sigma.length <= 2) {
    return failCheck(`${codePrefix}.MALFORMED_SIGMA`, "Sigma evidence must carry non-empty hex sigma.", safeRefs);
  }
  if (!isHex32(evidence.authority_ref)) {
    return failCheck(`${codePrefix}.AUTHORITY_REF_MALFORMED`, "Sigma evidence authority_ref must be 32-byte hex.", safeRefs);
  }
  if (evidence.public_after_reveal !== true) {
    return failCheck(`${codePrefix}.NOT_PUBLIC_AFTER_REVEAL`, "Sigma evidence must be marked public_after_reveal.", safeRefs);
  }
  if (evidence.attestation_ref !== undefined && !isHex32(evidence.attestation_ref)) {
    return failCheck(`${codePrefix}.ATTESTATION_REF_MALFORMED`, "Sigma evidence attestation_ref must be 32-byte hex.", safeRefs);
  }
  return passCheck(`${codePrefix}.PASS`, safeRefs);
}
