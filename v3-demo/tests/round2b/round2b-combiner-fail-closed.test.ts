// Step 4 — combiner fail-closed abort.
//
// Verifies (a) combiner.invocationCount === 1 (orchestrateSigmas dispatched
// but snapshot-verifier threw before reconstructFileKey), (b)
// Shamir.combine count === 0 (NEVER called), (c) AEAD decrypt count === 0
// (NEVER reached).
//
// Per S2-1 §1.7 + §14: any blocking refusal observed in the snapshot →
// throw CustodyError → toFailure → return { ok: false } from
// combineAndDecrypt. NO Shamir.combine, NO AEAD, NO partial plaintext.

import { describe, it, expect } from "vitest";
import {
  runRound2b,
  makeDefaultRound2bDependencies,
  simulateCombinerFailClosedOnRefusal,
} from "../../src/rounds/round2b.js";
import { RefusalCode } from "@cealis/v3-api";

describe("Round 2b — combiner fail-closed (S2-1 §1.7 + §14)", () => {
  it("Shamir.combine NEVER called during Round 2b", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.shamirCombineCount).toBe(0);
  });

  it("AEAD decrypt NEVER reached during Round 2b", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.aeadDecryptCount).toBe(0);
  });

  it("combineAndDecrypt invoked exactly once (snapshot-verifier path)", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.combinerInvocationCount).toBe(1);
  });

  it("DecryptResult shape mirrors upstream toFailure() output", async () => {
    // The simulate-helper produces what combineAndDecrypt would return on
    // a real authorizationSnapshot with refusalState.refused === true.
    const result = simulateCombinerFailClosedOnRefusal({ reasonCode: RefusalCode.Art17Erasure });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("CUSTODY_ERR_G4_REFUSED");
      expect(result.subCodes).toEqual(["REASON_0x02"]);
      expect(result.metadata).toBeDefined();
    }
  });

  it("Fail-closed produces NO plaintext field on the result", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.combinerResult.ok).toBe(false);
    if (!result.combinerResult.ok) {
      expect("plaintext" in result.combinerResult).toBe(false);
    }
  });
});
