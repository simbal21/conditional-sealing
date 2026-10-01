// assembleRefusalDelivery — convenience wrapper over handleG4Refusal that
// returns BOTH the persisted entry AND the constructed webhook envelope in
// one call.
//
// Closes an internal integration-gap item (2026-05-14).

import { describe, expect, it } from "vitest";
import {
  assembleRefusalDelivery,
  handleG4Refusal,
  InMemoryG4RefusalStore,
  RefusalCode,
  isBlockingRefusal,
  isEncryptedReason,
  type RefusalCodeValue,
} from "../../src/index.js";
import type { Hex32 } from "../../src/types/reveal-artifact-bundle.js";

const ZERO_HEX32 = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex32;

const ALL_REASON_CODES: readonly RefusalCodeValue[] = [
  RefusalCode.LegalCompel,
  RefusalCode.Art17Erasure,
  RefusalCode.Art18Restriction,
  RefusalCode.IntegrityFail,
  RefusalCode.ChainMismatch,
  RefusalCode.PluginDeprecated,
  RefusalCode.AuthorityDeprecated,
  RefusalCode.DslDeprecated,
  RefusalCode.OracleDeprecated,
  RefusalCode.OptOutActive,
];

function makeDeps() {
  const captured: Array<unknown> = [];
  return {
    store: new InMemoryG4RefusalStore(),
    eventBus: {
      emit: (event: unknown): void => {
        captured.push(event);
      },
    },
    captured,
    now: () => new Date("2026-05-11T00:00:00.000Z"),
  };
}

describe("assembleRefusalDelivery — composes handleG4Refusal + envelope", () => {
  for (const code of ALL_REASON_CODES) {
    const codeHex = `0x${code.toString(16).padStart(2, "0")}`;
    it(`returns entry + webhook for code ${codeHex}`, async () => {
      const deps = makeDeps();
      const result = await assembleRefusalDelivery(
        {
          authorizationId: ZERO_HEX32,
          h_commit: ZERO_HEX32,
          partner_id: "demo-partner",
          pda_id: "demo-pda",
          reason_code: code,
          ...(isEncryptedReason(code)
            ? { encrypted_reason_ref: `vault://encrypted-reasons/${codeHex}` }
            : {}),
        },
        deps,
      );

      // entry shape
      expect(result.entry.reason_code).toBe(code);
      expect(result.entry.reason_code_hex).toBe(codeHex);
      expect(result.entry.partner_id).toBe("demo-partner");
      expect(result.entry.pda_id).toBe("demo-pda");
      expect(result.blocking).toBe(isBlockingRefusal(code));
      expect(result.advisory).toBe(!isBlockingRefusal(code));

      // store persistence (handleG4Refusal contract preserved)
      expect(deps.store.entries).toHaveLength(1);
      expect(deps.store.entries[0]).toEqual(result.entry);

      // webhook envelope shape
      expect(result.webhook.event_id).toBe(result.entry.refusal_id);
      expect(result.webhook.event_type).toBe("g4.refused");
      expect(result.webhook.schema_version).toBe("s2-5.1");
      expect(result.webhook.partner_id).toBe("demo-partner");
      expect(result.webhook.pda_id).toBe("demo-pda");
      expect(result.webhook.created_at).toBe(result.entry.refused_at);

      // data discriminator
      const data = result.webhook.data;
      expect(data["authorizationId"]).toBe(ZERO_HEX32);
      expect(data["h_commit"]).toBe(ZERO_HEX32);
      expect(data["reason_code"]).toBe(codeHex);
      expect(data["reason_label"]).toBe(result.entry.reason_label);
      expect(data["reason_visibility"]).toBe(result.entry.reason_visibility);
      expect(data["blocking"]).toBe(result.entry.blocking);
      if (isEncryptedReason(code)) {
        expect(data["encrypted_reason_ref"]).toBe(result.entry.encrypted_reason_ref);
      } else {
        expect(data["encrypted_reason_ref"]).toBeUndefined();
      }

      // eventBus side-emit preserved (matches handleG4Refusal behavior)
      expect(deps.captured).toHaveLength(1);
    });
  }
});

describe("assembleRefusalDelivery — failure semantics propagate from handleG4Refusal", () => {
  it("rejects encrypted reasons missing encrypted_reason_ref", async () => {
    const deps = makeDeps();
    await expect(
      assembleRefusalDelivery(
        {
          authorizationId: ZERO_HEX32,
          h_commit: ZERO_HEX32,
          partner_id: "demo-partner",
          pda_id: "demo-pda",
          reason_code: RefusalCode.Art17Erasure,
          // encrypted_reason_ref OMITTED on purpose — should reject
        },
        deps,
      ),
    ).rejects.toThrow();
  });

  it("returned entry matches what handleG4Refusal would have produced standalone", async () => {
    // Call both pathways with identical inputs and assert byte-equal entry.
    const refDeps = makeDeps();
    const wrapperDeps = makeDeps();
    const input = {
      authorizationId: ZERO_HEX32,
      h_commit: ZERO_HEX32,
      partner_id: "demo-partner",
      pda_id: "demo-pda",
      reason_code: RefusalCode.IntegrityFail,
    } as const;
    const direct = await handleG4Refusal(input, refDeps);
    const wrapped = await assembleRefusalDelivery(input, wrapperDeps);
    expect(wrapped.entry).toEqual(direct.entry);
    expect(wrapped.blocking).toBe(direct.blocking);
    expect(wrapped.advisory).toBe(direct.advisory);
  });
});
