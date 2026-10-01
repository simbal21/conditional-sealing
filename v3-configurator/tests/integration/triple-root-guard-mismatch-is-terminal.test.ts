import { describe, expect, it } from "vitest";
import {
  TerminalEmissionFailure,
  tripleRootGuard,
} from "../../src/pda/triple-root-guard.js";

describe("§8.6 triple-root guard", () => {
  it("throws terminal emission failure on any root mismatch", () => {
    const local = new Uint8Array(32);
    const helper = new Uint8Array(32);
    const emitted = new Uint8Array(32);
    emitted[31] = 1;

    expect(() => tripleRootGuard({ local, contractHelper: helper, emittedEvent: emitted })).toThrow(
      TerminalEmissionFailure,
    );
  });
});
