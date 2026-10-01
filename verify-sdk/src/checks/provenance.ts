import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import {
  failCheck,
  isHex32,
  passCheck,
  requiredString,
  safeRefsFromBundle,
  skippedCheck,
} from "./canonicalization.js";

export function checkProvenance(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  const provenance = bundle.provenance;
  if (provenance.status === "not_configured") {
    return skippedCheck("PROVENANCE.NOT_CONFIGURED", refs);
  }
  if (provenance.status !== "present" || !isHex32(provenance.p15_attestations_root)) {
    return failCheck("PROVENANCE.MALFORMED", "Provenance block is malformed.", refs);
  }
  if (!isHex32(provenance.attestor_registry_ref.entry_digest)) {
    return failCheck("PROVENANCE.REGISTRY_REF_MALFORMED", "Attestor registry ref is malformed.", refs);
  }
  for (const attestation of provenance.field_attestations) {
    if (
      !requiredString(attestation.field_path) ||
      !isHex32(attestation.field_hash) ||
      !requiredString(attestation.attestor_id) ||
      !requiredString(attestation.attestor_signing_key_id) ||
      !requiredString(attestation.signature_alg) ||
      !isHex32(attestation.signed_payload_digest) ||
      !requiredString(attestation.signature) ||
      !Array.isArray(attestation.merkle_proof) ||
      attestation.merkle_proof.some((item) => !isHex32(item))
    ) {
      return failCheck("PROVENANCE.FIELD_ATTESTATION_MALFORMED", "A provenance field attestation is malformed.", refs);
    }
  }
  return passCheck("PROVENANCE.PASS", refs);
}
