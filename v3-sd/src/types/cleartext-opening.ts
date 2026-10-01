// Cleartext-opening mode catalog per §4.4 lines 466-477 + §12.1 lines 1117-1124.
//
// LOCKED defaults (§4.4 line 477 normative):
//   - DEFAULT for regulated partner integrations: `cleartext_zk_opened`
//   - Alternate (TEE attestation): `cleartext_attested` — must be marked
//     explicitly in `SdBundle.cleartext[*].opening_mode`.
//
// Two-mode coverage (§4.4 lines 470-477):
//
//   Mode 1 (cleartext_zk_opened — DEFAULT): PLONK equality proof
//     Prove:
//       field_commitment = Poseidon5(tag, authorization_scalar, field_id, salt, value)
//       value = public_cleartext_encoded
//       leaf(field_id, field_commitment, policy) is in sdMerkleRoot
//
//   Mode 2 (cleartext_attested): TEE-attestation-only opening
//     Onboarding response marks field as `cleartext_attested`;
//     partner verification rests on the SD TEE attestation chain rather than
//     a circuit proof.

import { CLEARTEXT_OPENING_MODE, type CleartextOpeningModeCode } from "./sd-field-policy.js";

export { CLEARTEXT_OPENING_MODE };
export type { CleartextOpeningModeCode };

export const CLEARTEXT_OPENING_DEFAULT_MODE = CLEARTEXT_OPENING_MODE.ZK_OPENED;
export const CLEARTEXT_OPENING_DEFAULT_LABEL = "cleartext_zk_opened" as const;

export type CleartextOpeningLabel = "none" | "cleartext_zk_opened" | "cleartext_attested";

/** Bidirectional code ↔ label table for SDK + bundle assembly. */
export const CLEARTEXT_OPENING_MODE_LABEL: Readonly<Record<CleartextOpeningModeCode, CleartextOpeningLabel>> = Object.freeze({
  [CLEARTEXT_OPENING_MODE.NONE]: "none",
  [CLEARTEXT_OPENING_MODE.ZK_OPENED]: "cleartext_zk_opened",
  [CLEARTEXT_OPENING_MODE.TEE_ATTESTED]: "cleartext_attested",
});

export const CLEARTEXT_OPENING_LABEL_MODE: Readonly<Record<CleartextOpeningLabel, CleartextOpeningModeCode>> = Object.freeze({
  none: CLEARTEXT_OPENING_MODE.NONE,
  cleartext_zk_opened: CLEARTEXT_OPENING_MODE.ZK_OPENED,
  cleartext_attested: CLEARTEXT_OPENING_MODE.TEE_ATTESTED,
});
