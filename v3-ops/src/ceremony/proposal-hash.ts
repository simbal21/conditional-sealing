import { keccak_256 } from "@noble/hashes/sha3";
import * as canonicalizeModule from "canonicalize";
import type { Hex } from "viem";

const canonicalize = (
  canonicalizeModule as unknown as {
    readonly default: (input: unknown) => string | undefined;
  }
).default;

/**
 * Deterministic proposal hash for a ceremony. Inputs are canonicalized via
 * RFC 8785 JCS so two parties building the same proposal converge on the
 * same bytes. This is NOT a contract-side commitment hash — those use the
 * TAG_*_V3 domain separation locked in S2-1 §2.3. Proposal hashes here
 * serve as deterministic ceremony identifiers in logs and runbooks.
 */
export function proposalHash(payload: Record<string, unknown>): Hex {
  const canon = canonicalize(payload);
  if (canon === undefined) {
    throw new Error("PROPOSAL_HASH_CANONICALIZATION_FAILED");
  }
  const digest = keccak_256(new TextEncoder().encode(canon));
  return ("0x" + bytesToHex(digest)) as Hex;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Build a unique ceremony id from slug + timestamp. NOT cryptographically
 * secure — just for log/audit identification.
 */
export function generateCeremonyId(slug: string): `0x${string}` {
  const seed = `${slug}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const digest = keccak_256(new TextEncoder().encode(seed));
  return ("0x" + bytesToHex(digest)) as `0x${string}`;
}
