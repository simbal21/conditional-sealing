import { describe, expect, it } from "vitest";

import { aggregateClaimProof } from "../../src/prove/index.js";
import type { ComposedExprNode } from "../../src/types/index.js";

function fieldId(n: number): Uint8Array {
  const out = new Uint8Array(32);
  out[31] = n;
  return out;
}

describe("composed Claim TS-side aggregation", () => {
  it("aggregates equality + range + set leaves without compiling composed.circom", () => {
    const equalityField = fieldId(1);
    const rangeField = fieldId(2);
    const setField = fieldId(3);
    const expr: ComposedExprNode = {
      kind: "and",
      children: [
        { kind: "leaf", predicate: "equality", field_id: equalityField, params: ["55"] },
        {
          kind: "or",
          children: [
            { kind: "leaf", predicate: "range", field_id: rangeField, params: ["18", "99", "64"] },
            { kind: "leaf", predicate: "set_membership", field_id: setField, params: ["setRoot"] },
          ],
        },
      ],
    };

    const result = aggregateClaimProof(expr, [
      {
        leafId: Buffer.from(equalityField).toString("hex"),
        predicate: "equality",
        verified: true,
        fieldId: "1",
        publicSignals: ["1"],
        proofDigestHex: "aa",
      },
      {
        leafId: Buffer.from(rangeField).toString("hex"),
        predicate: "range",
        verified: true,
        fieldId: "2",
        publicSignals: ["2"],
        proofDigestHex: "bb",
      },
    ]);

    expect(result.verified).toBe(true);
    expect(result.depth).toBe(3);
    expect(result.leaves).toBe(3);
    expect(result.fields).toBe(3);
    expect(result.aggregationProofDigestHex).toMatch(/^[0-9a-f]{64}$/);
  });
});
