// Step 3 — terminal state after ShredFinalized: M2 ShredRegistry's
// `getCurrentShredState(hCommit)` returns the terminal `Shredded` value.
//
// In CI dry-run we surface this via the round2 result. Live mode reads the
// view via the M2 ABI on the deployed ShredRegistry.

import { describe, it, expect } from "vitest";
import {
  runRound2,
  makeDefaultRound2Dependencies,
  type Round2ContractAddresses,
} from "../../src/rounds/round2.js";

const ADDRESSES: Round2ContractAddresses = {
  conditionEngine: "0x9999999999999999999999999999999999999999",
  shredRegistry: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

describe("Round 2 — terminal Shredded state (S2-2 §10.6)", () => {
  it("ShredRegistry currentShredState === 'Shredded' after run", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.chainState.currentShredState).toBe("Shredded");
  });

  it("ShredRequested fires BEFORE ShredFinalized (per S2-6 §11 queue→execute ordering)", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    // We assert event ordering by looking at the ceremony's emittedEvents.
    const events = result.ceremonyOutcome.emittedEvents;
    const requestedIndex = events.indexOf("ShredRequested");
    const finalizedIndex = events.indexOf("ShredFinalized");
    expect(requestedIndex).toBeGreaterThanOrEqual(0);
    expect(finalizedIndex).toBeGreaterThanOrEqual(0);
    expect(requestedIndex).toBeLessThan(finalizedIndex);
  });

  it("Round 2 captures proofShred (public verification token, NOT key material)", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    // proofShred is set by ceremony.execute() (dry-run uses 0xdd...dd).
    expect(result.proofShred).not.toBeNull();
    expect(result.proofShred?.startsWith("0x")).toBe(true);
  });

  it("hCommit + authorizationId are stable hex32 values for downstream assertions", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.hCommit.startsWith("0x")).toBe(true);
    expect(result.hCommit.length).toBe(2 + 64); // hex32 = 0x + 64 chars
    expect(result.authorizationId.startsWith("0x")).toBe(true);
    expect(result.authorizationId.length).toBe(2 + 64);
  });
});
