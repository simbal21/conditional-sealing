import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalizeAcc, type JsonValue } from "../../src/g2-lit/acc-canonicalize.js";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "vendor", "lit");
const acc = JSON.parse(readFileSync(join(fixtureDir, "acc-fixture.json"), "utf8")) as JsonValue;

describe("G2 Lit ACC canonicalization", () => {
  it("produces byte-identical output for equivalent JSON with different key order", () => {
    const shuffled = {
      predicates: (acc as { predicates: JsonValue }).predicates,
      reveal: (acc as { reveal: JsonValue }).reveal,
      protocol: (acc as { protocol: JsonValue }).protocol,
      contracts: (acc as { contracts: JsonValue }).contracts,
      version: (acc as { version: JsonValue }).version,
      chain: (acc as { chain: JsonValue }).chain,
    };
    expect(canonicalizeAcc(shuffled)).toEqual(canonicalizeAcc(acc));
  });
});
