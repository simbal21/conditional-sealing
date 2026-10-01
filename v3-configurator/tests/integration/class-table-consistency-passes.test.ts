import { describe, expect, it } from "vitest";
import { runClassTableConsistencyCheck } from "../../src/validate/class-table/consistency-check.js";

describe("@cealis/v3-configurator — §5.4 class-table consistency", () => {
  it("runs all 12 §5.4 checks and passes the canonical table", () => {
    const results = runClassTableConsistencyCheck();

    expect(results).toHaveLength(12);
    expect(results.every((entry) => entry.pass)).toBe(true);
    expect(results.map((entry) => entry.name)).toEqual([
      "physical executable row count is 103",
      "integer root ids are contiguous from 1 through 91",
      "child ids are unique, suffixed under an existing integer root, and contiguous within that root",
      "surface_name values are unique",
      "every row has exactly one test_exited_on",
      "every category (a) row has a governance sub-class or composition",
      "every category (b)/(c) row has a PDA+ allow-list or bound",
      "every cross_ref_to_pda_root_field maps to an allowed spec or off-chain PDA JSON anchor",
      'no duplicate "issuer mode" row exists',
      "every row id referenced by the coverage sidecar exists",
      "all 9 condition modules appear at least once in the coverage sidecar",
      "all 7 views appear at least once in the coverage sidecar",
    ]);
  });
});

