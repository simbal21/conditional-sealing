// Commit-time DEK dealer (F-CRYPTO-2) — the EXACT inverse of §6.3 Shamir.combine.
//
// Per internal design record dek-lifecycle.md and docs/specs/cryptography-spec.md §6.2/§6.3:
// at commit time the TEE generates a random 32-byte DEK and Shamir-splits it into
// `n = 3 + n_conditional` shares with threshold `k = 3 + k_conditional`. Each share is
// later §6.2-wrapped to its gate-recipient pubkey. This file produces those typed
// `ShareRecord`s such that the existing `combineDek` reconstructs the DEK for each profile.
//
// Field: GF(2^8) with the AES irreducible polynomial 0x11b. We reuse the SAME `gfMul`/`gfAdd`
// from shamir.ts — there is one field implementation, constant-time, shared by deal + combine.
//
// Access-structure topology (must mirror shamir.ts combine EXACTLY):
//   FIXED_ONLY        — 3-of-3 over {Lit(x=1), G3(x=2), G4(x=3)}; top-level split k=3,n=3.
//   RECIPIENT_1_OF_1  — 4-of-4 over {Lit(x=1), G3(x=2), G4(x=3), RECIPIENT_AGGREGATE(x=4)};
//                       top-level split k=4,n=4; the aggregate is a DIRECT top-level share.
//   RECIPIENT_K_OF_N  — 4-of-4 top {Lit(x=1), G3(x=2), G4(x=3), aggregate(x=4, NOT emitted)};
//                       the aggregate top-share is itself split into a nested
//                       k_conditional-of-n_conditional RECIPIENT_BRANCH; only the 3 fixed
//                       top shares + the n_conditional branch shares are emitted. The combiner
//                       reconstructs the aggregate from any k_conditional branch shares, then
//                       combines it with the 3 fixed top shares.
//
// Share x-coordinates (the §6.3.2 invariant the combiner enforces):
//   TOP_LEVEL:        x = logical_index + 1  (Lit=1, G3=2, G4=3, RECIPIENT_AGGREGATE=4)
//   RECIPIENT_BRANCH: x = recipient_index + 1 (1..n_conditional)
//
// Security: the dealer draws REAL polynomial coefficients from a CSPRNG, so each share is a
// distinct, information-theoretically-independent point on a degree-(k-1) polynomial — NOT the
// degenerate every-share==DEK shortcut. A single share (or any below-threshold subset) is zero
// information on the DEK (Shamir property), which is what makes the universal tripwire hold
// cryptographically under single-gate-key compromise (dek-lifecycle.md §"Why A1+Shamir works").

import { randomBytes } from "@noble/hashes/utils.js";

import {
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_LIT,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  validateShareRecord,
  type ShareRecord,
  type ShareRole,
} from "../codecs/share-record.js";
import type { Bytes32 } from "../types.js";
import { gfAdd, gfMul, type AccessStructureProfile } from "./shamir.js";

const DEK_BYTES = 32;

export const DealError = {
  ERR_DEAL_DEK_LENGTH: "ERR_DEAL_DEK_LENGTH",
  ERR_DEAL_PROFILE_INVALID: "ERR_DEAL_PROFILE_INVALID",
  ERR_DEAL_RANDOMNESS_INSUFFICIENT: "ERR_DEAL_RANDOMNESS_INSUFFICIENT",
} as const;

export type DealErrorCode = keyof typeof DealError;

export class DealDekError extends Error {
  constructor(
    public readonly code: DealErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "DealDekError";
  }
}

/**
 * Coefficient source. Defaults to the platform CSPRNG (`@noble/hashes` `randomBytes`,
 * the same source `hybrid-wrap.ts` uses). Injectable for deterministic round-trip tests
 * (NEVER used in production — production always uses the CSPRNG default).
 */
export type RandomBytesFn = (length: number) => Uint8Array;

export interface DealDekOptions {
  /** Test-only deterministic coefficient source. Omit in production. */
  randomBytesFn?: RandomBytesFn;
}

function assertDek(dek: Bytes32): void {
  if (!(dek instanceof Uint8Array) || dek.length !== DEK_BYTES) {
    throw new DealDekError("ERR_DEAL_DEK_LENGTH", `DEK must be exactly ${DEK_BYTES} bytes`);
  }
}

function assertProfile(profile: AccessStructureProfile): void {
  if (profile.kind === "RECIPIENT_K_OF_N") {
    const { n_conditional, k_conditional } = profile;
    if (
      !Number.isInteger(n_conditional) ||
      !Number.isInteger(k_conditional) ||
      n_conditional < 1 ||
      n_conditional > 0xff ||
      k_conditional < 1 ||
      k_conditional > n_conditional
    ) {
      throw new DealDekError(
        "ERR_DEAL_PROFILE_INVALID",
        "RECIPIENT_K_OF_N requires 1 <= k_conditional <= n_conditional <= 255",
      );
    }
  }
}

/**
 * Draw `count` non-zero, mutually-distinct uniform GF(2^8) coefficients (one byte each).
 * Non-zero is required so the leading coefficient is non-degenerate (true degree = k-1, no
 * accidental collapse to a lower-degree polynomial that would leak structure). We re-draw on a
 * zero byte rather than mapping 0→something, to keep the distribution uniform over {1..255}.
 */
function drawNonzeroByte(rnd: RandomBytesFn): number {
  // Pull a small batch and scan for a non-zero byte; refill if a batch is all-zero.
  for (let attempt = 0; attempt < 64; attempt++) {
    const batch = rnd(16);
    if (!(batch instanceof Uint8Array) || batch.length < 1) {
      throw new DealDekError("ERR_DEAL_RANDOMNESS_INSUFFICIENT", "randomBytesFn returned no bytes");
    }
    for (let i = 0; i < batch.length; i++) {
      const b = batch[i] ?? 0;
      if (b !== 0) return b;
    }
  }
  throw new DealDekError("ERR_DEAL_RANDOMNESS_INSUFFICIENT", "could not draw a non-zero coefficient");
}

/**
 * Byte-sliced Shamir SPLIT — exact inverse of `lagrangeAtZero`/`combineByteLane`.
 *
 * For each of the 32 lanes independently, build a degree-(k-1) polynomial whose constant term is
 * `secret[lane]` and whose higher coefficients are drawn per-lane from the CSPRNG. Evaluate at
 * x = 1..n via Horner-equivalent power accumulation in GF(2^8). Any k of the n evaluation points
 * reconstruct the constant term — this is precisely what the combiner relies on.
 *
 * Coefficients: the leading coefficient (degree k-1) is non-zero (true degree); intermediate
 * coefficients are uniform over the full byte range. This matches the algebra of the locked
 * positive goldens (which lie on real, non-degenerate polynomials), while drawing real entropy
 * rather than the test helper's deterministic generator.
 */
function splitSecret(secret: Uint8Array, k: number, n: number, rnd: RandomBytesFn): Uint8Array[] {
  const shares: Uint8Array[] = Array.from({ length: n }, () => new Uint8Array(DEK_BYTES));
  for (let lane = 0; lane < DEK_BYTES; lane++) {
    // coeffs[0] = degree-1 term ... coeffs[k-2] = degree-(k-1) leading term.
    const coeffs: number[] = [];
    for (let degree = 1; degree <= k - 1; degree++) {
      // Leading coefficient must be non-zero so the polynomial truly has degree k-1.
      const isLeading = degree === k - 1;
      if (isLeading) {
        coeffs.push(drawNonzeroByte(rnd));
      } else {
        const b = rnd(1);
        if (!(b instanceof Uint8Array) || b.length < 1) {
          throw new DealDekError("ERR_DEAL_RANDOMNESS_INSUFFICIENT", "randomBytesFn returned no bytes");
        }
        coeffs.push(b[0] ?? 0);
      }
    }
    for (let x = 1; x <= n; x++) {
      let y = secret[lane] ?? 0;
      let xPower = 1;
      for (const coeff of coeffs) {
        xPower = gfMul(xPower, x);
        y = gfAdd(y, gfMul(coeff, xPower));
      }
      const share = shares[x - 1];
      if (share === undefined) {
        throw new DealDekError("ERR_DEAL_RANDOMNESS_INSUFFICIENT", `share ${x} missing`);
      }
      share[lane] = y;
    }
  }
  return shares;
}

function mustShare(shares: Uint8Array[], index: number, label: string): Uint8Array {
  const share = shares[index];
  if (share === undefined) {
    throw new DealDekError("ERR_DEAL_RANDOMNESS_INSUFFICIENT", `${label} share missing`);
  }
  return share;
}

function topRecord(role: ShareRole, logicalIndex: number, value: Uint8Array): ShareRecord {
  const record: ShareRecord = {
    share_domain: SHARE_DOMAIN_TOP_LEVEL,
    share_role: role,
    logical_index: logicalIndex,
    x: logicalIndex + 1,
    value,
  };
  validateShareRecord(record);
  return record;
}

function recipientRecord(recipientIndex: number, value: Uint8Array): ShareRecord {
  const record: ShareRecord = {
    share_domain: SHARE_DOMAIN_RECIPIENT_BRANCH,
    share_role: SHARE_ROLE_CONDITIONAL_RECIPIENT,
    logical_index: recipientIndex,
    x: recipientIndex + 1,
    value,
  };
  validateShareRecord(record);
  return record;
}

/**
 * Deal a 32-byte DEK into typed `ShareRecord`s for the given access-structure profile.
 *
 * Round-trip guarantee: `combineDek(dealDek(dek, profile), profile).dek === dek` for every
 * profile, and any below-threshold subset (or a wrong-branch substitution) fails to combine.
 *
 * @param dek     the 32-byte data-encryption key (TEE-generated at commit; destroyed after deal)
 * @param profile the PDA-selected access structure (NOT hardcoded — comes from
 *                `conditional_recipients_policy`; platform principle)
 */
export function dealDek(dek: Bytes32, profile: AccessStructureProfile, options: DealDekOptions = {}): ShareRecord[] {
  assertDek(dek);
  assertProfile(profile);
  const rnd: RandomBytesFn = options.randomBytesFn ?? ((length: number) => randomBytes(length));

  // Work on a copy so callers can zero their original DEK independently.
  const secret = dek.slice();

  if (profile.kind === "FIXED_ONLY") {
    // 3-of-3 top-level split over {Lit, G3, G4}.
    const shares = splitSecret(secret, 3, 3, rnd);
    return [
      topRecord(SHARE_ROLE_LIT, 0, mustShare(shares, 0, "lit")),
      topRecord(SHARE_ROLE_G3, 1, mustShare(shares, 1, "g3")),
      topRecord(SHARE_ROLE_G4, 2, mustShare(shares, 2, "g4")),
    ];
  }

  // Both recipient profiles split the DEK into a 4-of-4 top level first.
  const topShares = splitSecret(secret, 4, 4, rnd);

  if (profile.kind === "RECIPIENT_1_OF_1") {
    // The 4th top share is the recipient aggregate, emitted directly as a top-level share.
    return [
      topRecord(SHARE_ROLE_LIT, 0, mustShare(topShares, 0, "lit")),
      topRecord(SHARE_ROLE_G3, 1, mustShare(topShares, 1, "g3")),
      topRecord(SHARE_ROLE_G4, 2, mustShare(topShares, 2, "g4")),
      topRecord(SHARE_ROLE_RECIPIENT_AGGREGATE, 3, mustShare(topShares, 3, "aggregate")),
    ];
  }

  // RECIPIENT_K_OF_N: the 4th top share (the aggregate) is itself split into a nested
  // k_conditional-of-n_conditional RECIPIENT_BRANCH. The aggregate top share is NOT emitted —
  // the combiner reconstructs it from any k_conditional branch shares.
  const aggregate = mustShare(topShares, 3, "aggregate");
  const recipientShares = splitSecret(aggregate, profile.k_conditional, profile.n_conditional, rnd);
  return [
    topRecord(SHARE_ROLE_LIT, 0, mustShare(topShares, 0, "lit")),
    topRecord(SHARE_ROLE_G3, 1, mustShare(topShares, 1, "g3")),
    topRecord(SHARE_ROLE_G4, 2, mustShare(topShares, 2, "g4")),
    ...recipientShares.map((value, recipientIndex) => recipientRecord(recipientIndex, value)),
  ];
}

/** Alias matching the `split` naming in the F-CRYPTO-2 task framing. Identical to `dealDek`. */
export const splitDek = dealDek;

export const DekDealer = {
  deal: dealDek,
} as const;
