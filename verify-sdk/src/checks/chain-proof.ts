import { verifyRevealAuthorizedReceipt } from "../chain-reader/partner-rpc.js";
import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import type { CheckContext } from "./canonicalization.js";
import {
  failCheck,
  isHex32,
  normalizeHex32,
  passCheck,
  safeRefsFromBundle,
} from "./canonicalization.js";

export async function checkChainProof(
  bundle: RevealArtifactBundle,
  context: CheckContext,
): Promise<VerifyCheck> {
  const refs = safeRefsFromBundle(bundle);
  const chain = bundle.chain_proofs;
  if (
    !isHex32(chain.commit_tx_hash) ||
    !isHex32(chain.commit_block_hash) ||
    !isHex32(chain.reveal_authorized_tx_hash) ||
    !isHex32(chain.reveal_authorized_block_hash) ||
    !isHex32(chain.receipt_proof.block_hash)
  ) {
    return failCheck("CHAIN_PROOF.MALFORMED_HEX", "Chain proof contains malformed hash fields.", refs);
  }
  if (chain.reveal_authorized_block !== bundle.authorization.authorization_block) {
    return failCheck("CHAIN_PROOF.AUTHORIZATION_BLOCK_MISMATCH", "Authorization block does not match chain proof.", refs);
  }
  if (normalizeHex32(chain.reveal_authorized_block_hash) !== normalizeHex32(bundle.authorization.authorization_block_hash)) {
    return failCheck("CHAIN_PROOF.AUTHORIZATION_BLOCK_HASH_MISMATCH", "Authorization block hash does not match chain proof.", refs);
  }
  if (chain.receipt_proof.block_number !== chain.reveal_authorized_block) {
    return failCheck("CHAIN_PROOF.RECEIPT_BLOCK_MISMATCH", "Receipt block number does not match RevealAuthorized block.", refs);
  }
  if (normalizeHex32(chain.receipt_proof.block_hash) !== normalizeHex32(chain.reveal_authorized_block_hash)) {
    return failCheck("CHAIN_PROOF.RECEIPT_BLOCK_HASH_MISMATCH", "Receipt block hash does not match RevealAuthorized block hash.", refs);
  }
  if (chain.receipt_proof.log_index !== chain.reveal_authorized_log_index) {
    return failCheck("CHAIN_PROOF.LOG_INDEX_MISMATCH", "Receipt log index does not match RevealAuthorized log index.", refs);
  }
  if (chain.conditionRef !== undefined && normalizeHex32(chain.conditionRef) !== normalizeHex32(bundle.authorization.conditionRef)) {
    return failCheck("CHAIN_PROOF.CONDITION_REF_MISMATCH", "Condition ref does not match authorization.", refs);
  }
  if (Date.parse(bundle.authorization.challenge_window_expired_at) > context.now.getTime()) {
    return failCheck("CHAIN_PROOF.CHALLENGE_WINDOW_OPEN", "Challenge window has not expired.", refs);
  }
  if (context.options.requireOnlineRegistryChecks === true) {
    if (context.options.chainRpcUrl === undefined) {
      return failCheck("CHAIN_PROOF.RPC_URL_REQUIRED", "Online chain proof requested without partner-supplied chainRpcUrl.", refs);
    }
    const online = await verifyRevealAuthorizedReceipt({
      chainRpcUrl: context.options.chainRpcUrl,
      chainId: chain.chain_id,
      txHash: chain.reveal_authorized_tx_hash,
      expectedBlockHash: chain.reveal_authorized_block_hash,
      expectedLogIndex: chain.reveal_authorized_log_index,
    });
    if (!online.ok) {
      return failCheck("CHAIN_PROOF.ONLINE_RECEIPT_MISMATCH", online.reason, refs);
    }
  }
  return passCheck("CHAIN_PROOF.PASS", refs);
}
