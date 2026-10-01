import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export const PUBLIC_INPUT_ORDER = Object.freeze([
  "authorization_scalar",
  "h_commit_scalar",
  "partner_scalar",
  "pda_scalar",
  "claim_scalar",
  "field_set_digest_scalar",
  "sdMerkleRoot",
  "predicate_param_0",
  "predicate_param_1",
  "predicate_param_2",
  "expiry_timestamp",
  "revocation_scalar",
  "verifier_ref_scalar",
  "proof_context_scalar",
] as const);

export type PublicInputName = typeof PUBLIC_INPUT_ORDER[number];
export type PublicInputRecord = Readonly<Record<PublicInputName, bigint>>;

export const PUBLIC_INPUT_COUNT = 14 as const;

export function publicInputSchemaDigestHex(): string {
  return bytesToHex(keccak_256(new TextEncoder().encode(JSON.stringify(PUBLIC_INPUT_ORDER))));
}

export function toPublicInputArray(input: PublicInputRecord): string[] {
  return PUBLIC_INPUT_ORDER.map((name) => input[name].toString());
}

export function assertCanonicalPublicInputOrder(actual: readonly string[]): void {
  if (actual.length !== PUBLIC_INPUT_ORDER.length) {
    throw new Error(`PUBLIC_INPUT_ORDER_DRIFT: expected 14 slots, got ${actual.length}`);
  }
  for (let i = 0; i < PUBLIC_INPUT_ORDER.length; i++) {
    if (actual[i] !== PUBLIC_INPUT_ORDER[i]) {
      throw new Error(`PUBLIC_INPUT_ORDER_DRIFT at ${i}: ${actual[i] ?? "<missing>"}`);
    }
  }
}
