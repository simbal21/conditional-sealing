import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import {
  failCheck,
  isHex32,
  normalizeHex32,
  passCheck,
  safeRefsFromBundle,
} from "./canonicalization.js";

export function checkShredState(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  const shred = bundle.shred_state;
  if (!isHex32(shred.h_commit) || normalizeHex32(shred.h_commit) !== normalizeHex32(bundle.authorization.h_commit)) {
    return failCheck("SHRED_STATE.H_COMMIT_MISMATCH", "Shred state h_commit does not match authorization h_commit.", refs);
  }
  const state = shred.shred_state.toLowerCase();
  if (
    state === "finalized" ||
    state === "shred_finalized" ||
    state === "shredded" ||
    state === "deleted" ||
    state === "vault_deleted"
  ) {
    return failCheck("SHRED_STATE.FINALIZED_BEFORE_REVEAL", "Finalized shred state blocks future reveal.", refs);
  }
  if (shred.checked_at_block_hash !== undefined && !isHex32(shred.checked_at_block_hash)) {
    return failCheck("SHRED_STATE.CHECKED_HASH_MALFORMED", "Shred checked_at_block_hash is malformed.", refs);
  }
  return passCheck("SHRED_STATE.PASS", refs);
}
