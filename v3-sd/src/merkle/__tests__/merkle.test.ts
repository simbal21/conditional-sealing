import { describe, expect, it } from "vitest";
import { buildBinaryPoseidonTree } from "../tree.js";
import { verifyMerklePath } from "../path-verification.js";
import { b32 } from "../../../tests/integration/helpers.js";

describe("binary Poseidon Merkle tree", () => {
  it("builds non-empty leaf-to-root paths and verifies them", () => {
    const tree = buildBinaryPoseidonTree([
      { field_index: 0, field_id: b32("f0"), field_commitment: 11n, policy: 1 },
      { field_index: 1, field_id: b32("f1"), field_commitment: 12n, policy: 2 },
    ]);
    expect(tree.paths[0]?.length).toBe(1);
    expect(
      verifyMerklePath({
        field_index: 0,
        field_id: b32("f0"),
        field_commitment: 11n,
        policy: 1,
        path: tree.paths[0] ?? [],
        expected_root: tree.root,
      }),
    ).toBe(true);
  });
});
