import type { Hex32 } from "@cealis/v3-crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";
import type { GateRecipientPubkeyEntry } from "../types/gate-recipient.js";
import type { LitAssignmentRecord } from "../types/registries.js";
import {
  bytesToHex,
  canonicalizeAcc,
  keccakHex,
  type JsonValue,
} from "./acc-canonicalize.js";
import type { LitDcapVerification } from "./dcap-verify.js";

export type LitShareDomain = "TOP_LEVEL";
export type LitShareRole = "LIT";

export interface LitKemBindingTuple {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
  readonly litKemPubkeyDigest: Hex32;
  readonly assignedTeeId: Hex32;
  readonly assignedTeePubkeyDigest: Hex32;
  readonly assignmentBlock: bigint;
  readonly accessStructureProfile: string;
  readonly stanzaIndex: 0;
  readonly shareDomain: LitShareDomain;
  readonly shareRole: LitShareRole;
}

export interface LitKemBindingProof {
  readonly method: "tee-local-statement";
  readonly tupleDigest: Hex32;
}

export interface VerifyLitKemBindingProofInput {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
  readonly kemPubkeyEntry: GateRecipientPubkeyEntry;
  readonly assignment: LitAssignmentRecord;
  readonly accessStructureProfile: string;
  readonly proof: LitKemBindingProof | null | undefined;
  readonly verifiedQuote: LitDcapVerification;
}

export function computeLitKemPubkeyDigest(kemPubkey: Uint8Array): Hex32 {
  return keccakHex([kemPubkey]);
}

export function buildLitKemBindingTuple(
  input: Omit<VerifyLitKemBindingProofInput, "proof" | "verifiedQuote">,
): LitKemBindingTuple {
  return {
    authorizationId: input.authorizationId,
    hCommit: input.hCommit,
    blockHash: input.blockHash,
    litKemPubkeyDigest: computeLitKemPubkeyDigest(input.kemPubkeyEntry.kemPubkey),
    assignedTeeId: input.assignment.assignedTeeId,
    assignedTeePubkeyDigest: bytesToHex(keccak_256(input.assignment.assignedTeePubkey)),
    assignmentBlock: input.assignment.assignmentBlock,
    accessStructureProfile: input.accessStructureProfile,
    stanzaIndex: 0,
    shareDomain: "TOP_LEVEL",
    shareRole: "LIT",
  };
}

export function computeLitKemBindingTupleDigest(tuple: LitKemBindingTuple): Hex32 {
  const canonical: JsonValue = {
    access_structure_profile: tuple.accessStructureProfile,
    assignedTeeId: tuple.assignedTeeId,
    assignedTeePubkeyDigest: tuple.assignedTeePubkeyDigest,
    assignmentBlock: tuple.assignmentBlock.toString(),
    authorizationId: tuple.authorizationId,
    block_hash: tuple.blockHash,
    h_commit: tuple.hCommit,
    lit_kem_pubkey_digest: tuple.litKemPubkeyDigest,
    share_domain: tuple.shareDomain,
    share_role: tuple.shareRole,
    stanza_index: tuple.stanzaIndex,
  };
  return keccakHex([canonicalizeAcc(canonical)]);
}

export function verifyLitKemBindingProof(input: VerifyLitKemBindingProofInput): void {
  if (input.proof === null || input.proof === undefined) {
    throw mismatch("Lit KEM-to-assignment binding proof missing");
  }
  const tuple = buildLitKemBindingTuple(input);
  const expectedDigest = computeLitKemBindingTupleDigest(tuple);
  if (input.proof.tupleDigest !== expectedDigest) {
    throw mismatch("Lit KEM-to-assignment binding proof digest mismatch");
  }
  if (!input.verifiedQuote.bindingStatementDigests.includes(expectedDigest)) {
    throw mismatch("Lit KEM binding proof is not carried by the per-op TEE quote");
  }
}

function mismatch(message: string): CustodyError {
  return new CustodyError(
    CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
    message,
  );
}
