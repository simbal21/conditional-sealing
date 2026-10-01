import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Hex32 } from "@cealis/v3-crypto";
import { CUSTODY_ERROR_CODES } from "../../src/errors.js";
import { verifyLitDcapQuote } from "../../src/g2-lit/dcap-verify.js";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "vendor", "lit");
const sigma = JSON.parse(readFileSync(join(fixtureDir, "sigma-vector.json"), "utf8")) as { authorizationId: Hex32; h_commit: Hex32; block_hash: Hex32 };
const quote = JSON.parse(readFileSync(join(fixtureDir, "dcap-fixture.json"), "utf8")) as Record<string, unknown>;

describe("G2 Lit quote replay rejection", () => {
  it("rejects a quote whose user_data is bound to another tuple", () => {
    expect(() =>
      verifyLitDcapQuote({
        quote: { ...quote, userData: "0x" + "11".repeat(64) },
        authorizationId: sigma.authorizationId,
        hCommit: sigma.h_commit,
        blockHash: sigma.block_hash,
        nowMs: 1_800_000_060_000,
      }),
    ).toThrow(CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_QUOTE_REPLAY);
  });
});
