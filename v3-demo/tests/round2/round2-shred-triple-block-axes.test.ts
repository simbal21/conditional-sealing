// Round 2 triple-block axes per S2-2 §10.4 + S2-6 §11.3:
//
//   Axis 1: G1 chain refuses future reveal authorization (ConditionEngine
//           refuses to emit RevealAuthorized for shredded hCommit).
//   Axis 2: Vault ciphertext deleted (vault.exists(hCommit) === false).
//   Axis 3: G4 Phase 1 refuses future σ_G4 for shredded hCommit.

import { describe, it, expect } from "vitest";
import {
  runRound2,
  makeDefaultRound2Dependencies,
  type Round2ContractAddresses,
} from "../../src/rounds/round2.js";

const ADDRESSES: Round2ContractAddresses = {
  conditionEngine: "0x3333333333333333333333333333333333333333",
  shredRegistry: "0x4444444444444444444444444444444444444444",
};

describe("Round 2 — triple-block axes (S2-2 §10.4 + S2-6 §11.3)", () => {
  it("Axis 1 — G1 chain refusal: zero RevealAuthorized events in shred window", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.revealAuthorizedAbsent).toBe(true);
  });

  it("Axis 2 — vault ciphertext deletion: vault.exists === false after shred", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    // Dry-run path treats the ciphertext as logically deleted after the
    // execute-stage simulates deletion (per ShredTriggerCeremony.execute
    // dry-run branch). Live mode calls vaultClient.deleteCiphertext.
    expect(result.vaultExistsAfterShred).toBe(false);
  });

  it("Axis 3 — G4 Phase 1 marks subject shredded; future σ_G4 fail-closed", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.g4Phase1MarkedShredded).toBe(true);
    // Future σ_G4 requests would observe this state via
    // g4Phase1Mock.isShredded(hCommit). We verify the spy is set; the
    // fail-closed behavior at the G4 adapter layer is exercised in M3
    // tests, not here.
    expect(deps.g4Phase1Mock.isShredded(result.hCommit)).toBe(true);
  });

  it("All 3 axes are simultaneously verified — no axis can be 'partially blocked'", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.revealAuthorizedAbsent && !result.vaultExistsAfterShred && result.g4Phase1MarkedShredded).toBe(true);
  });
});
