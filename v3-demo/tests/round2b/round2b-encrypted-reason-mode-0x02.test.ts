// Step 5 — encrypted-reason mode is the DEFAULT for code 0x02 per S2-2
// §14.3 / S2-5 §10.4.
//
// Encrypted-reason invariant: codes 0x02 (Art. 17 erasure) and 0x03 (Art. 18
// restriction) MUST carry an `encrypted_reason_ref` and MUST be marked
// reason_visibility === "encrypted". Plaintext disclosure of the reason
// would be a GDPR violation. The reason payload is decryptable ONLY by the
// authorized recipient (the partner or, in some legal regimes, a court).

import { describe, it, expect } from "vitest";
import {
  runRound2b,
  makeDefaultRound2bDependencies,
} from "../../src/rounds/round2b.js";
import { RefusalCode } from "@cealis/v3-api";

describe("Round 2b — encrypted-reason mode 0x02 (S2-2 §14.3)", () => {
  it("0x02 produces encrypted reason_visibility by default", async () => {
    const deps = makeDefaultRound2bDependencies({ reasonCode: RefusalCode.Art17Erasure });
    const result = await runRound2b(deps);
    expect(result.refusalEntry.reason_visibility).toBe("encrypted");
  });

  it("0x02 carries an encrypted_reason_ref (mandatory under §14.3)", async () => {
    const deps = makeDefaultRound2bDependencies({ reasonCode: RefusalCode.Art17Erasure });
    const result = await runRound2b(deps);
    expect(result.refusalEntry.encrypted_reason_ref).toBeDefined();
    expect(typeof result.refusalEntry.encrypted_reason_ref).toBe("string");
    expect((result.refusalEntry.encrypted_reason_ref ?? "").length).toBeGreaterThan(0);
  });

  it("Recipient verify surfaces the encryptedReasonRef in the result", async () => {
    const deps = makeDefaultRound2bDependencies({ reasonCode: RefusalCode.Art17Erasure });
    const result = await runRound2b(deps);
    expect(result.recipientVerify.reasonVisibility).toBe("encrypted");
    expect(result.recipientVerify.encryptedReasonRef).toBeDefined();
  });

  it("Webhook event data carries the encrypted_reason_ref (off-chain partner delivery)", async () => {
    const deps = makeDefaultRound2bDependencies({ reasonCode: RefusalCode.Art17Erasure });
    const result = await runRound2b(deps);
    expect(result.webhookEvent.data.encrypted_reason_ref).toBeDefined();
    expect(result.webhookEvent.data.reason_visibility).toBe("encrypted");
  });

  it("Plaintext reason value is NEVER present in any surface for 0x02", async () => {
    const deps = makeDefaultRound2bDependencies({ reasonCode: RefusalCode.Art17Erasure });
    const result = await runRound2b(deps);
    // No "reason_text" / "reason_plaintext" / "decrypted_reason" / etc.
    // Only encrypted_reason_ref is permitted.
    const entryStr = JSON.stringify(result.refusalEntry).toLowerCase();
    expect(entryStr).not.toContain("reason_text");
    expect(entryStr).not.toContain("reason_plaintext");
    expect(entryStr).not.toContain("decrypted_reason");

    const eventStr = JSON.stringify(result.webhookEvent.data).toLowerCase();
    expect(eventStr).not.toContain("reason_text");
    expect(eventStr).not.toContain("reason_plaintext");
    expect(eventStr).not.toContain("decrypted_reason");
  });
});
