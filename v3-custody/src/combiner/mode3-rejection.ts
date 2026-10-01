import type { AgeEnvelopeOutput } from "../m1-imports.js";
import type { SigmaEvidenceBundle } from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { metadataNumber, metadataString } from "./jcs-canonicalize.js";

export function rejectMode3(input: {
  readonly envelope: AgeEnvelopeOutput;
  readonly sigmas: SigmaEvidenceBundle;
}): void {
  for (const evidence of input.sigmas.evidence) {
    const mode = metadataNumber(evidence.metadata, "deliveryMode");
    const modeLabel = metadataString(evidence.metadata, "deliveryMode");
    if (mode === 3 || modeLabel === "WALLET_EIP1271" || modeLabel === "MODE3") {
      throw mode3Error();
    }
  }

  for (const stanza of input.envelope.stanzas) {
    if (stanza.conditional_recipient_mac === undefined) continue;
    const maybeMode = stanza.ciphertext_payload_bytes[0];
    if (maybeMode === 0x03) throw mode3Error();
  }
}

function mode3Error(): CustodyError {
  return new CustodyError(
    CUSTODY_ERROR_CODES.CUSTODY_ERR_MODE3_RESERVED,
    "Mode 3 conditional recipient is reserved at V2 launch",
    { subCodes: ["ERR_MODE_3_NOT_SHIPPED_AT_V2"] },
  );
}
