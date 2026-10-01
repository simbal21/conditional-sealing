// TS-CRYPTO-F-08 closure tests — `canonicalAddressPin` is now MANDATORY at
// the type-level, the assertion fires INSIDE `runPreVerifyPipeline` (as
// the FIRST pre-verify step alongside C1), and a NEW cross-substitution
// invariant (`pin.chainId === commitSnapshot.snapshot.chainId`) catches
// an attacker pinning one chain while consuming another's snapshot.
//
// Defect class closed (Security-audit-2026-05-14 TS-CRYPTO-F-08):
//   The combiner used to rely solely on a subscription-time address filter
//   in `registry-reader.ts`, with the address sourced from a user-injectable
//   deployment manifest. A compromised manifest could redirect the combiner
//   to subscribe to events from an attacker-controlled "fake ConditionEngine"
//   emitting forged `RevealAuthorized` topics.
//
//   The original opt-in form (`if (input.canonicalAddressPin !== undefined)`
//   at `combine-and-decrypt.ts:59` pre-R2b-3) made the canonical assertion
//   caller-supplied — production deployments that forgot the pin silently
//   ran without the check. This was the F-08 vulnerability surface.
//
// New invariants enforced (R2b-3 closure 2026-05-20):
//   (i) `canonicalAddressPin` is REQUIRED on `CombineAndDecryptInput` and
//       on `runPreVerifyPipeline` input — no `?` boundary. Constructing
//       either input without the pin is a typecheck error.
//   (ii) The canonical-address assertion runs as the FIRST pre-verify
//        step, unconditionally, against `assertCanonicalConditionEngineAddress`.
//   (iii) `pin.chainId === commitSnapshot.snapshot.chainId` — pinning
//         mainnet while consuming a sepolia snapshot (or vice versa) is
//         caught at byte level by the new cross-substitution gate.

import type { Address } from "viem";
import { describe, expect, it } from "vitest";
import {
  combineAndDecrypt,
  dispatchProfile,
  runPreVerifyPipeline,
} from "../../src/combiner/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../../src/errors.js";
import { CanonicalAddressMismatchError } from "../../src/chain/canonical-addresses.js";
import { makeFixture, PLAINTEXT } from "./combiner-testkit.js";

const CANONICAL_BASE_SEPOLIA_ADDRESS = "0xb09a8300423CA3BD0E028bAB6A6245A248520D02" as Address;
const NON_CANONICAL_ADDRESS = "0x0000000000000000000000000000000000000001" as Address;
const BASE_SEPOLIA_CHAIN_ID = 84_532;
const BASE_MAINNET_CHAIN_ID = 8_453;

describe("combiner canonicalAddressPin — TS-CRYPTO-F-08 mandatory closure", () => {
  it("sanity: canonical pin (default testkit fixture) passes through the combiner end-to-end", () => {
    // The testkit fixture default IS the canonical Base Sepolia entry, so
    // the unmodified happy-path must continue to decrypt. This is the
    // existence proof that the new mandatory check didn't break the
    // happy-path.
    const base = makeFixture();
    const result = combineAndDecrypt(base);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });

  it("non-canonical configuredConditionEngine on a known chainId refuses inside the combiner (the F-08 attack class)", () => {
    // This is the F-08 attack: an attacker injects a "fake ConditionEngine"
    // address into the deployment manifest, on a chainId we DO have a
    // canonical entry for. The pipeline-internal assertion refuses to
    // fire — the combiner cannot be redirected to subscribe to forged
    // RevealAuthorized topics. Under the old opt-in code path this would
    // have proceeded silently when the caller omitted the pin entirely;
    // now there is no "omit the pin" path.
    //
    // `combineAndDecrypt` swallows exceptions and returns a structured
    // failure (see `toFailure` in `combine-and-decrypt.ts`). The
    // `CanonicalAddressMismatchError` is NOT a `CustodyError`, so it
    // funnels through the generic-error branch
    // (CUSTODY_ERR_COMBINER_BINARY_MISMATCH / ERR_COMBINER_UNEXPECTED_ABORT)
    // with the original error message in `metadata.reason`. This is the
    // operational shape the caller actually observes.
    const base = makeFixture();
    const result = combineAndDecrypt({
      ...base,
      canonicalAddressPin: {
        configuredConditionEngine: NON_CANONICAL_ADDRESS,
        chainId: BASE_SEPOLIA_CHAIN_ID,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_COMBINER_UNEXPECTED_ABORT");
      // The original CanonicalAddressMismatchError's message bubbles into
      // metadata.reason — confirms the refusal came from F-08's assertion,
      // not some other class of failure.
      expect(String(result.metadata?.reason ?? "")).toContain("Canonical ConditionEngine address mismatch");
    }
  });

  it("unknown chainId (no canonical entry) is refused by the combiner", () => {
    // An attacker that pins a chainId we have no canonical entry for is
    // refused — there is no entry to match against, so we cannot prove
    // canonicality and the combiner refuses to bind. NB: we have to also
    // align the snapshot's chainId to the same unknown value, otherwise
    // the cross-substitution gate fires first (separately tested below).
    const base = makeFixture();
    const unknownChainId = 999_999;
    const result = combineAndDecrypt({
      ...base,
      canonicalAddressPin: {
        configuredConditionEngine: CANONICAL_BASE_SEPOLIA_ADDRESS,
        chainId: unknownChainId,
      },
      registrySnapshots: {
        ...base.registrySnapshots,
        commitSnapshot: {
          ...base.registrySnapshots.commitSnapshot,
          snapshot: {
            ...base.registrySnapshots.commitSnapshot.snapshot,
            chainId: unknownChainId,
          },
        },
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_COMBINER_UNEXPECTED_ABORT");
      expect(String(result.metadata?.reason ?? "")).toContain("Canonical ConditionEngine address mismatch");
    }
  });

  it("pin.chainId ≠ commitSnapshot.snapshot.chainId throws ERR_CANONICAL_PIN_CHAIN_MISMATCH (cross-substitution gate, NEW at R2b-3)", () => {
    // This is the substitution attack the original opt-in form did NOT
    // catch, even when the caller passed a pin: an attacker pins Base
    // mainnet (8453) while the snapshot was taken on Base sepolia
    // (84_532), or vice versa. Each input is internally consistent
    // (mainnet canonical address matches the mainnet entry once that's
    // populated; sepolia snapshot is fine), but the consumer is binding
    // to data from different chains. The new gate refuses.
    //
    // We use sepolia snapshot + mainnet pin so the canonical-address
    // assertion would PASS for the mainnet entry (once populated) — but
    // the chainId mismatch fires first.
    const base = makeFixture();
    const result = (() => {
      try {
        const dispatchedProfile = dispatchProfile({
          commitAAD: base.commitAAD,
          sigmas: base.sigmas,
        });
        runPreVerifyPipeline({
          authorizationId: base.authorizationId,
          hCommit: base.hCommit,
          authorizationBlock: base.authorizationBlock,
          blockHash: base.blockHash,
          commitAADBytes: base.commitAAD,
          ageEnvelope: base.ageEnvelope,
          sigmas: base.sigmas,
          profileDispatch: dispatchedProfile,
          registrySnapshots: base.registrySnapshots,
          canonicalAddressPin: {
            configuredConditionEngine: CANONICAL_BASE_SEPOLIA_ADDRESS,
            chainId: BASE_MAINNET_CHAIN_ID, // intentional substitution
          },
        });
        return { ok: true as const };
      } catch (error) {
        if (error instanceof CustodyError) {
          return { ok: false as const, code: error.code, subCodes: error.subCodes };
        }
        throw error;
      }
    })();

    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);
      expect(result.subCodes).toContain("ERR_CANONICAL_PIN_CHAIN_MISMATCH");
    }
  });

  it("case-insensitive hex match: lowercase address against EIP-55-checksummed canonical entry still passes", () => {
    // The canonical-addresses module documents case-insensitive matching
    // (per its `toLowerCase()` comparison). Verify by passing the
    // canonical Base Sepolia address as all-lowercase — this is the
    // production-realistic case where the caller normalized the address
    // through a different lib than the one that produced the canonical
    // constant.
    const base = makeFixture();
    const result = combineAndDecrypt({
      ...base,
      canonicalAddressPin: {
        configuredConditionEngine:
          CANONICAL_BASE_SEPOLIA_ADDRESS.toLowerCase() as Address,
        chainId: BASE_SEPOLIA_CHAIN_ID,
      },
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });

  it("the canonical-pin assertion is UNCONDITIONAL — `runPreVerifyPipeline` runs it on EVERY call, with no opt-in guard", () => {
    // Behavioral proof that GATE-3 (no inverse-skip) applies to F-08: a
    // direct `runPreVerifyPipeline` call with a non-canonical pin throws
    // immediately, regardless of any other input shape. Under the
    // pre-R2b-3 opt-in code path, omitting the pin (undefined) would have
    // silently proceeded — that omission path no longer exists in the
    // type system, and a non-canonical pin always refuses.
    const base = makeFixture();
    const dispatchedProfile = dispatchProfile({
      commitAAD: base.commitAAD,
      sigmas: base.sigmas,
    });
    expect(() =>
      runPreVerifyPipeline({
        authorizationId: base.authorizationId,
        hCommit: base.hCommit,
        authorizationBlock: base.authorizationBlock,
        blockHash: base.blockHash,
        commitAADBytes: base.commitAAD,
        ageEnvelope: base.ageEnvelope,
        sigmas: base.sigmas,
        profileDispatch: dispatchedProfile,
        registrySnapshots: base.registrySnapshots,
        canonicalAddressPin: {
          configuredConditionEngine: NON_CANONICAL_ADDRESS,
          chainId: BASE_SEPOLIA_CHAIN_ID,
        },
      }),
    ).toThrow(CanonicalAddressMismatchError);
  });
});
