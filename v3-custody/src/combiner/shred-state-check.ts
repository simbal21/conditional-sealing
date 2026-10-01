import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import {
  isShredStateSignable,
  type AuthorizationRegistrySnapshot,
} from "../types/index.js";

export function assertShredStateSignable(snapshot: AuthorizationRegistrySnapshot): void {
  if (!isShredStateSignable(snapshot.currentShredState)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHRED_STATE_BLOCKED,
      `ShredRegistry.currentShredState is non-signable: ${snapshot.currentShredState}`,
    );
  }
}
