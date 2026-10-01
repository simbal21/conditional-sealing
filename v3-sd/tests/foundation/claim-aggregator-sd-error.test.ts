// HARD-1 resolution test (2026-05-13): claim-aggregator cap violations throw
// SdError (not plain Error) per §1.3 error model.
//
// dw-quality REJECTED Phase E because `claim-aggregator.ts` lines 53/57/58/65
// threw plain `new Error("COMPOSED_CAP_*_EXCEEDED")` instances, breaking the
// §1.3 contract: partner SDK callers cannot catch via `instanceof SdError`,
// and the §1.4 safeRefs allow-list does not apply.
//
// Resolution: all 4 throw sites refactored to throw `SdError` with code
// `FIELD_POLICY_UNKNOWN` (closest §1.3 fit — composed expression policy is
// invalid) and `safeRefs` carrying only allow-list keys.

import { describe, expect, it } from "vitest";

import { ALLOWED_SAFE_REF_KEYS, SdError, SdErrorCode } from "../../src/errors/index.js";
import { measureComposed } from "../../src/prove/claim-aggregator.js";
import type { ComposedExprNode } from "../../src/types/composed.js";

const POLICY_CODES = [
  "COMPOSED_CAP_DEPTH_EXCEEDED",
  "COMPOSED_CAP_LEAVES_EXCEEDED",
  "COMPOSED_CAP_FIELDS_EXCEEDED",
  "COMPOSED_EMPTY_BRANCH",
];

const FORBIDDEN_TOKENS = ["proof", "plaintext", "salt", "witness"];

function leaf(fieldHex: string): ComposedExprNode {
  return {
    kind: "leaf",
    field_id: new Uint8Array(Buffer.from(fieldHex.padStart(64, "0"), "hex")) as ComposedExprNode extends { field_id: infer F } ? F : never,
    predicate: "equality",
    params: [],
  };
}

function andNode(children: ComposedExprNode[]): ComposedExprNode {
  return { kind: "and", children };
}

function deepNode(depth: number): ComposedExprNode {
  let node: ComposedExprNode = leaf("01");
  for (let i = 0; i < depth; i += 1) {
    node = { kind: "not", child: node };
  }
  return node;
}

function manyLeavesNode(count: number, sharedField: boolean): ComposedExprNode {
  const leaves: ComposedExprNode[] = [];
  for (let i = 0; i < count; i += 1) {
    leaves.push(leaf(sharedField ? "01" : (i + 1).toString(16)));
  }
  return andNode(leaves);
}

describe("HARD-1 resolution: claim-aggregator throws SdError, not plain Error", () => {
  it("MAX_DEPTH overflow throws SdError with FIELD_POLICY_UNKNOWN", () => {
    let thrown: unknown;
    try {
      measureComposed(deepNode(10));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(SdError);
    const e = thrown as SdError;
    expect(e.code).toBe(SdErrorCode.FIELD_POLICY_UNKNOWN);
    expect(e.stage).toBe("schema_validation");
    expect(e.safeRefs.policy_code).toBe("COMPOSED_CAP_DEPTH_EXCEEDED");
    expect(e.safeRefs.claim_type).toBe("composed");
  });

  it("MAX_LEAVES overflow throws SdError with FIELD_POLICY_UNKNOWN", () => {
    let thrown: unknown;
    try {
      measureComposed(manyLeavesNode(40, true));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(SdError);
    const e = thrown as SdError;
    expect(e.code).toBe(SdErrorCode.FIELD_POLICY_UNKNOWN);
    expect(e.safeRefs.policy_code).toBe("COMPOSED_CAP_LEAVES_EXCEEDED");
  });

  it("MAX_FIELDS overflow throws SdError with FIELD_POLICY_UNKNOWN", () => {
    let thrown: unknown;
    try {
      measureComposed(manyLeavesNode(20, false));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(SdError);
    const e = thrown as SdError;
    expect(e.code).toBe(SdErrorCode.FIELD_POLICY_UNKNOWN);
    expect(e.safeRefs.policy_code).toBe("COMPOSED_CAP_FIELDS_EXCEEDED");
  });

  it("empty branch throws SdError with FIELD_POLICY_UNKNOWN", () => {
    let thrown: unknown;
    try {
      measureComposed(andNode([]));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(SdError);
    const e = thrown as SdError;
    expect(e.code).toBe(SdErrorCode.FIELD_POLICY_UNKNOWN);
    expect(e.safeRefs.policy_code).toBe("COMPOSED_EMPTY_BRANCH");
  });

  it("every safeRefs key sits in the §1.4 allow-list (no PII leak)", () => {
    const tests: (() => void)[] = [
      () => measureComposed(deepNode(10)),
      () => measureComposed(manyLeavesNode(40, true)),
      () => measureComposed(manyLeavesNode(20, false)),
      () => measureComposed(andNode([])),
    ];
    for (const run of tests) {
      let thrown: unknown;
      try { run(); } catch (e) { thrown = e; }
      expect(thrown).toBeInstanceOf(SdError);
      const safeRefs = (thrown as SdError).safeRefs;
      for (const key of Object.keys(safeRefs)) {
        expect(
          (ALLOWED_SAFE_REF_KEYS as readonly string[]).includes(key),
          `safeRefs key "${key}" must sit in the §1.4 allow-list`,
        ).toBe(true);
      }
    }
  });

  it("safeRefs payload never leaks proof/plaintext/salt/witness tokens (defense-in-depth)", () => {
    const tests: (() => void)[] = [
      () => measureComposed(deepNode(10)),
      () => measureComposed(manyLeavesNode(40, true)),
      () => measureComposed(manyLeavesNode(20, false)),
      () => measureComposed(andNode([])),
    ];
    for (const run of tests) {
      let thrown: unknown;
      try { run(); } catch (e) { thrown = e; }
      const serialized = JSON.stringify((thrown as SdError).safeRefs).toLowerCase();
      for (const token of FORBIDDEN_TOKENS) {
        expect(serialized, `safeRefs payload must not contain "${token}"`).not.toContain(token);
      }
    }
  });

  it("HARD-1 source-level grep: no plain `throw new Error(\"COMPOSED_\")` in claim-aggregator", async () => {
    // Source-level tripwire — fails if anyone re-introduces plain Error throws.
    const { readFile } = await import("node:fs/promises");
    const { resolve } = await import("node:path");
    const source = await readFile(
      resolve(__dirname, "..", "..", "src", "prove", "claim-aggregator.ts"),
      "utf-8",
    );
    for (const code of POLICY_CODES) {
      expect(
        source,
        `claim-aggregator must throw SdError carrying policy_code=${code}, not plain Error`,
      ).not.toMatch(new RegExp(`throw new Error\\("${code}"\\)`));
    }
    expect(source).toContain("throw new SdError(SdErrorCode.FIELD_POLICY_UNKNOWN");
  });
});
