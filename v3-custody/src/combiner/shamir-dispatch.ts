import { combineDek, type ShareRecord } from "../m1-imports.js";
import type { AccessStructureProfile } from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";

export function reconstructFileKey(input: {
  readonly shares: readonly ShareRecord[];
  readonly profile: AccessStructureProfile;
}): Uint8Array {
  const result = combineDek([...input.shares], input.profile);
  if (!result.ok) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      `M1 Shamir.combine rejected typed access structure: ${result.error}`,
      { subCodes: [result.error] },
    );
  }
  return result.dek;
}
