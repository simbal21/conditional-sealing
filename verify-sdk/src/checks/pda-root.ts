import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import {
  failCheck,
  isHex32,
  normalizeHex32,
  passCheck,
  safeRefsFromBundle,
} from "./canonicalization.js";

export function checkPdaRoot(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  if (!isHex32(bundle.pda.pda_root)) {
    return failCheck("PDA_ROOT.MALFORMED", "pda_root must be a 32-byte hex string.", refs);
  }
  const topicPdaRoot = bundle.chain_proofs.reveal_authorized_topics[2];
  if (topicPdaRoot !== undefined && isHex32(topicPdaRoot) && normalizeHex32(topicPdaRoot) !== normalizeHex32(bundle.pda.pda_root)) {
    return failCheck("PDA_ROOT.EVENT_TOPIC_MISMATCH", "RevealAuthorized pda_root topic does not match bundle pda_root.", refs);
  }
  return passCheck("PDA_ROOT.PASS", refs);
}
