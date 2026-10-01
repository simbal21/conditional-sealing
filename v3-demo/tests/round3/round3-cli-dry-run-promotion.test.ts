// M8 Round 3 — CLI dry-run flag promotion (internal integration-gap item).
//
// Asserts that both `demo round3 --dry-run` and `DEMO_DRY_RUN=1 demo round3`
// land on the same structural code path. The CLI flag is promoted to the
// env var inside `dispatch()` before the round-name positional is resolved,
// so the round3 dispatcher sees `process.env.DEMO_DRY_RUN === "1"` either way.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { dispatch } from "../../src/cli.js";

describe("Round 3 — CLI dry-run flag promotion", () => {
  let original: string | undefined;

  beforeEach(() => {
    original = process.env.DEMO_DRY_RUN;
    delete process.env.DEMO_DRY_RUN;
  });

  afterEach(() => {
    if (original === undefined) delete process.env.DEMO_DRY_RUN;
    else process.env.DEMO_DRY_RUN = original;
  });

  it("dispatch(['round3', '--dry-run']) succeeds and sets DEMO_DRY_RUN=1", async () => {
    expect(process.env.DEMO_DRY_RUN).toBeUndefined();
    const exitCode = await dispatch(["round3", "--dry-run"]);
    expect(exitCode).toBe(0);
    // Confirms the env was promoted by the CLI flag handler.
    expect(process.env.DEMO_DRY_RUN).toBe("1");
  });

  it("dispatch(['round3']) with DEMO_DRY_RUN=1 in env also succeeds", async () => {
    process.env.DEMO_DRY_RUN = "1";
    const exitCode = await dispatch(["round3"]);
    expect(exitCode).toBe(0);
  });

  it("dispatch(['round3', '--dry-run']) keeps round-name positional intact", async () => {
    // Regression: if --dry-run isn't stripped before round-name resolution,
    // argv[0] would be "--dry-run" (or argv would be misaligned), and
    // round-resolution would fail with exitCode 2.
    const exitCode = await dispatch(["round3", "--dry-run"]);
    expect(exitCode).not.toBe(2);
    expect(exitCode).toBe(0);
  });
});
