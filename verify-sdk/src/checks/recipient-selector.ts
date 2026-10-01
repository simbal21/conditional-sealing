import type { RevealArtifactBundle, VerifyArtifactOptions, VerifyCheck } from "../types.js";
import {
  failCheck,
  isHex32,
  normalizeHex32,
  passCheck,
  safeRefsFromBundle,
} from "./canonicalization.js";

export function checkRecipientSelector(
  bundle: RevealArtifactBundle,
  options: VerifyArtifactOptions,
): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  if (options.expectedRecipientRef !== undefined && bundle.recipient.recipient_ref !== options.expectedRecipientRef) {
    return failCheck("RECIPIENT_SELECTOR.UNEXPECTED_RECIPIENT", "Bundle recipient_ref does not match expected recipient.", refs);
  }
  if (!isHex32(bundle.recipient.schema_selector_digest) || !isHex32(bundle.plaintext.schema_selector_digest)) {
    return failCheck("RECIPIENT_SELECTOR.SCHEMA_SELECTOR_MALFORMED", "Recipient selector digest is malformed.", refs);
  }
  if (normalizeHex32(bundle.recipient.schema_selector_digest) !== normalizeHex32(bundle.plaintext.schema_selector_digest)) {
    return failCheck("RECIPIENT_SELECTOR.SCHEMA_SELECTOR_MISMATCH", "Recipient selector digest does not match plaintext selector digest.", refs);
  }
  return passCheck("RECIPIENT_SELECTOR.PASS", refs);
}
