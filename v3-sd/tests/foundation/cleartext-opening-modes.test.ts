// Foundation test — §4.4 + §12.1 two-mode cleartext opening coverage.

import { describe, it, expect } from "vitest";
import {
  CLEARTEXT_OPENING_MODE,
  CLEARTEXT_OPENING_DEFAULT_MODE,
  CLEARTEXT_OPENING_DEFAULT_LABEL,
  CLEARTEXT_OPENING_MODE_LABEL,
  CLEARTEXT_OPENING_LABEL_MODE,
} from "../../src/types/cleartext-opening.js";

describe("§4.4 cleartext opening modes (two-mode coverage)", () => {
  it("CLEARTEXT_OPENING_MODE.NONE = 0", () => {
    expect(CLEARTEXT_OPENING_MODE.NONE).toBe(0);
  });

  it("CLEARTEXT_OPENING_MODE.ZK_OPENED = 1 (DEFAULT for regulated partner integrations)", () => {
    expect(CLEARTEXT_OPENING_MODE.ZK_OPENED).toBe(1);
    expect(CLEARTEXT_OPENING_DEFAULT_MODE).toBe(CLEARTEXT_OPENING_MODE.ZK_OPENED);
    expect(CLEARTEXT_OPENING_DEFAULT_LABEL).toBe("cleartext_zk_opened");
  });

  it("CLEARTEXT_OPENING_MODE.TEE_ATTESTED = 2", () => {
    expect(CLEARTEXT_OPENING_MODE.TEE_ATTESTED).toBe(2);
  });

  it("mode ↔ label bidirectional mapping consistency", () => {
    for (const [codeStr, label] of Object.entries(CLEARTEXT_OPENING_MODE_LABEL)) {
      const code = Number(codeStr);
      expect(CLEARTEXT_OPENING_LABEL_MODE[label]).toBe(code);
    }
  });
});
