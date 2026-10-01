// Round 2b main path — Steps 1-7 per the internal build brief.
//
// AXIS: G4 mid-flight refusal 0x02 art_17_erasure. Distinct from Round 2's
// G1 chain-block axis. ConditionEngine emits RevealAuthorized NORMALLY;
// combiner observes refusal in AuthorizationRegistrySnapshot → fail-closed.
//
// PHASE-PLAN §0 drift catch #9: This is a SEPARATE FIXTURE from Round 2.

import { describe, it, expect } from "vitest";
import {
  runRound2b,
  makeDefaultRound2bDependencies,
} from "../../src/rounds/round2b.js";
import { RefusalCode } from "@cealis/v3-api";

describe("Round 2b — G4 mid-flight refusal (S2-2 §14.2 + S2-3 §5)", () => {
  it("Step 2: RevealAuthorized fires NORMALLY (no shred state)", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.revealAuthorizedEmitted).toBe(true);
  });

  it("Step 3-4: combiner aborts fail-closed when G4 returns refusal 0x02", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.combinerResult.ok).toBe(false);
    if (!result.combinerResult.ok) {
      expect(result.combinerResult.code).toBe("CUSTODY_ERR_G4_REFUSED");
      expect(result.combinerResult.subCodes).toContain("REASON_0x02");
    }
  });

  it("Step 5: M5 handleG4Refusal produces a G4RefusalEntry with correct fields", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.refusalEntry.reason_code).toBe(RefusalCode.Art17Erasure);
    expect(result.refusalEntry.reason_code_hex).toBe("0x02");
    expect(result.refusalEntry.reason_label).toBe("art_17_erasure");
  });

  it("Step 5: refusal entry binds to authorizationId + hCommit + partner/pda", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.refusalEntry.authorization_id).toBe(result.authorizationId);
    expect(result.refusalEntry.h_commit).toBe(result.hCommit);
    expect(result.refusalEntry.partner_id).toBe(deps.partnerId);
    expect(result.refusalEntry.pda_id).toBe(deps.pdaId);
  });

  it("Step 6: recipient verify result has kind:'refusal' + reasonCode 0x02 + verified=true", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.recipientVerify.kind).toBe("refusal");
    expect(result.recipientVerify.reasonCode).toBe(0x02);
    expect(result.recipientVerify.verified).toBe(true);
  });

  it("subjectId uses demo-r2b- prefix (distinct from Round 2's demo-r2-)", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.subjectId.startsWith("demo-r2b-")).toBe(true);
  });
});
