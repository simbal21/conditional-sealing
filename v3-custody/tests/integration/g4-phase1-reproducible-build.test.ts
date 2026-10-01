import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

describe("G4 Phase 1 reproducible build", () => {
  it("builds byte-identical Phase 1 daemon artifacts", () => {
    const result = spawnSync("./build-verify.sh", {
      cwd: "g4-phase1",
      encoding: "utf8",
    });
    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
  }, 120_000);
});
