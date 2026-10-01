import { describe, expect, it } from "vitest";
import { aggregateClaimProof } from "../../src/prove/claim-aggregator.js";
import { b32 } from "./helpers.js";

describe("composed Claim E2E", () => {
  it("verifies depth 3, four leaves, and AND/OR/NOT mix within caps", () => {
    const f1 = b32("f1");
    const f2 = b32("f2");
    const f3 = b32("f3");
    const f4 = b32("f4");
    const expression = {
      kind: "and" as const,
      children: [
        { kind: "leaf" as const, predicate: "range" as const, field_id: f1, params: ["18", "99"] },
        {
          kind: "or" as const,
          children: [
            { kind: "leaf" as const, predicate: "equality" as const, field_id: f2, params: ["1"] },
            { kind: "leaf" as const, predicate: "set_membership" as const, field_id: f3, params: ["1", "2"] },
          ],
        },
        { kind: "not" as const, child: { kind: "leaf" as const, predicate: "non_equality" as const, field_id: f4, params: ["0"] } },
      ],
    };
    const proofs = [
      { leafId: Buffer.from(f1).toString("hex"), predicate: "range" as const, verified: true, fieldId: "f1", publicSignals: [], proofDigestHex: "01" },
      { leafId: Buffer.from(f2).toString("hex"), predicate: "equality" as const, verified: true, fieldId: "f2", publicSignals: [], proofDigestHex: "02" },
      { leafId: Buffer.from(f3).toString("hex"), predicate: "set_membership" as const, verified: false, fieldId: "f3", publicSignals: [], proofDigestHex: "03" },
      { leafId: Buffer.from(f4).toString("hex"), predicate: "non_equality" as const, verified: false, fieldId: "f4", publicSignals: [], proofDigestHex: "04" },
    ];
    const result = aggregateClaimProof(expression, proofs);
    expect(result.verified).toBe(true);
    expect(result.depth).toBe(3);
    expect(result.leaves).toBe(4);
    expect(result.fields).toBe(4);
  });
});
