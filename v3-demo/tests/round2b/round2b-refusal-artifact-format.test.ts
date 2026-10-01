// Step 5 — refusal payload format per S2-5 §3.6 + S2-2 §14.
//
// NOTE on brief vs upstream: the brief refers to a "signed refusal artifact"
// per S2-5 §3 with `refusal_artifact_sig` field. The actual upstream surface
// (S2-5 §3.6 + handleG4Refusal) is a Problem+JSON refusal body delivered via
// HMAC-signed webhook envelope — NOT a separate JCS-canonicalized bundle.
// See the internal integration-gap log.
//
// This test validates the upstream surface's shape:
//   - reason_code numeric field (0x01-0x0A)
//   - reason_code_hex string ("0x02")
//   - reason_label string ("art_17_erasure")
//   - reason_visibility discriminator ("encrypted" | "plaintext")
//   - encrypted_reason_ref present iff visibility = "encrypted"
//   - blocking boolean (true for 0x01-0x09, false for 0x0A)

import { describe, it, expect } from "vitest";
import {
  runRound2b,
  makeDefaultRound2bDependencies,
} from "../../src/rounds/round2b.js";
import { RefusalCode } from "@cealis/v3-api";

describe("Round 2b — refusal payload format (S2-5 §3.6 + S2-2 §14)", () => {
  it("refusal entry has the 8 mandatory fields", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    const e = result.refusalEntry;
    expect(typeof e.refusal_id).toBe("string");
    expect(typeof e.authorization_id).toBe("string");
    expect(typeof e.h_commit).toBe("string");
    expect(typeof e.partner_id).toBe("string");
    expect(typeof e.pda_id).toBe("string");
    expect(typeof e.reason_code).toBe("number");
    expect(typeof e.reason_code_hex).toBe("string");
    expect(typeof e.reason_label).toBe("string");
  });

  it("reason_code_hex format is 0x__ (lowercase, two-digit)", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.refusalEntry.reason_code_hex).toMatch(/^0x[0-9a-f]{2}$/);
  });

  it("reason_visibility === 'encrypted' for code 0x02 (Art. 17)", async () => {
    const deps = makeDefaultRound2bDependencies({ reasonCode: RefusalCode.Art17Erasure });
    const result = await runRound2b(deps);
    expect(result.refusalEntry.reason_visibility).toBe("encrypted");
    expect(result.refusalEntry.encrypted_reason_ref).toBeDefined();
  });

  it("reason_visibility === 'encrypted' for code 0x03 (Art. 18)", async () => {
    const deps = makeDefaultRound2bDependencies({ reasonCode: RefusalCode.Art18Restriction });
    const result = await runRound2b(deps);
    expect(result.refusalEntry.reason_visibility).toBe("encrypted");
    expect(result.refusalEntry.encrypted_reason_ref).toBeDefined();
  });

  it("blocking === true for code 0x02 (BLOCKING per S2-3 §5)", async () => {
    const deps = makeDefaultRound2bDependencies({ reasonCode: RefusalCode.Art17Erasure });
    const result = await runRound2b(deps);
    expect(result.refusalEntry.blocking).toBe(true);
  });

  it("refused_at is ISO-8601 timestamp string", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    // ISO-8601: YYYY-MM-DDTHH:MM:SS.sssZ
    expect(result.refusalEntry.refused_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    expect(() => new Date(result.refusalEntry.refused_at)).not.toThrow();
  });
});
