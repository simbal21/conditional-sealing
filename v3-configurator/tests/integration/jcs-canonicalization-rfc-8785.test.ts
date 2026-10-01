import { describe, expect, it } from "vitest";
import { canonicalizeJson } from "../../src/pda/content-hash.js";

describe("RFC 8785 JCS canonicalization", () => {
  it("sorts object keys deterministically", () => {
    expect(canonicalizeJson({ z: 1, a: { c: 3, b: 2 } })).toBe('{"a":{"b":2,"c":3},"z":1}');
  });
});
