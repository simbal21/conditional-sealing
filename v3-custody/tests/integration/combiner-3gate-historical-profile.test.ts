import { describe, expect, it } from "vitest";
import { combineAndDecrypt, readCommitVersion } from "../../src/combiner/index.js";
import { makeFixture, PLAINTEXT } from "./combiner-testkit.js";

describe("combiner historical 3-gate profile", () => {
  it("routes commit_version below 0x0302 through historical 3-gate compatibility", () => {
    const base = makeFixture();
    const commitAAD = new Uint8Array(base.commitAAD);
    commitAAD[128] = 0x01;
    commitAAD[129] = 0x03;
    expect(readCommitVersion(commitAAD)).toBe(0x0301);
    const result = combineAndDecrypt({ ...base, commitAAD });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });
});
