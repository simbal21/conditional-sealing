import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import {
  failCheck,
  isHex32,
  passCheck,
  requiredString,
  safeRefsFromBundle,
  skippedCheck,
} from "./canonicalization.js";

export function checkIssuerAttestation(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  const issuer = bundle.issuer_attestation;
  if (issuer.status === "not_configured") {
    return skippedCheck("ISSUER_ATTESTATION.NOT_CONFIGURED", refs);
  }
  if (
    issuer.status !== "present" ||
    !requiredString(issuer.issuer_id) ||
    !requiredString(issuer.issuer_signing_key_id) ||
    !requiredString(issuer.signature_alg) ||
    !requiredString(issuer.signature) ||
    !isHex32(issuer.signed_payload_digest) ||
    !isHex32(issuer.subject_commitment_v3) ||
    !requiredString(issuer.person_key_ref)
  ) {
    return failCheck("ISSUER_ATTESTATION.MALFORMED", "Issuer attestation envelope is malformed.", refs);
  }
  if (!isHex32(issuer.issuer_registry_ref.entry_digest)) {
    return failCheck("ISSUER_ATTESTATION.REGISTRY_REF_MALFORMED", "Issuer registry ref is malformed.", refs);
  }
  return passCheck("ISSUER_ATTESTATION.PASS", refs);
}
