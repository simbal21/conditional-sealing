import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import {
  failCheck,
  isHex32,
  passCheck,
  safeRefsFromBundle,
} from "./canonicalization.js";

export function checkEndpointAttestation(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  const g4 = bundle.sigma_block.sigma_g4;
  if (!isHex32(g4.authority_ref)) {
    return failCheck("ENDPOINT_ATTESTATION.G4_AUTHORITY_REF_MISSING", "G4 authority ref must be present.", refs);
  }
  if (g4.phase !== 1 && g4.phase !== 2) {
    return failCheck("ENDPOINT_ATTESTATION.G4_PHASE_MISSING", "G4 phase must be 1 or 2.", refs);
  }
  if (g4.attestation_ref !== undefined && !isHex32(g4.attestation_ref)) {
    return failCheck("ENDPOINT_ATTESTATION.ATTESTATION_REF_MALFORMED", "G4 attestation ref must be 32-byte hex when present.", refs);
  }
  return passCheck("ENDPOINT_ATTESTATION.PASS", refs);
}
