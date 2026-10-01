import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, combineAndDecrypt } from "../../src/index.js";
import { makeFixture } from "./combiner-testkit.js";

describe("combiner stanza MAC verification", () => {
  it("aborts before payload parse on stanza MAC failure", () => {
    const result = combineAndDecrypt(
      makeFixture({
        mutateAgeEnvelope(bytes) {
          const copy = new Uint8Array(bytes);
          copy[72] = (copy[72] ?? 0) ^ 0xff;
          return copy;
        },
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.subCodes[0]).toMatch(/STANZA|MAC/);
  });

  it("aborts on malformed age envelopes before sigma admission", () => {
    const base = makeFixture();
    const result = combineAndDecrypt({ ...base, ageEnvelope: new Uint8Array([0x01, 0x02]) });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);
  });
});
