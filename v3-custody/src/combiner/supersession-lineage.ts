import type { CommitAADInput } from "../m1-imports.js";
import type { SigmaEvidenceBundle } from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { isZero32, metadataString } from "./jcs-canonicalize.js";

export function verifySupersessionLineage(input: {
  readonly commitAAD: CommitAADInput;
  readonly sigmas: SigmaEvidenceBundle;
}): void {
  if (input.commitAAD.commit_generation === 0 && isZero32(input.commitAAD.superseded_commit_ref)) {
    return;
  }
  const verified = input.sigmas.evidence.some(
    (evidence) => metadataString(evidence.metadata, "supersessionLineageVerified") === "true",
  );
  if (!verified) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
      "supersession lineage evidence is missing for a non-zero commit generation",
      { subCodes: ["ERR_SUPERSEDED_COMMIT_LINEAGE_BROKEN"] },
    );
  }
}
