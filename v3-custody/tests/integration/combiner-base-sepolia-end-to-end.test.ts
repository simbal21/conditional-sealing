import { describe, expect, it } from "vitest";

describe("combiner Base Sepolia end-to-end scaffold", () => {
  it.skipIf(process.env.CEALIS_TESTNET_RUN !== "true")("runs against deployed M2 contracts when M8 enables the manifest", () => {
    expect(process.env.CEALIS_TESTNET_RUN).toBe("true");
  });
});
