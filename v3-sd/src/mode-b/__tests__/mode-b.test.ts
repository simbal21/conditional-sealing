import { describe, expect, it } from "vitest";
import { assertModeBSdCompatible } from "../rejection.js";
import { SdError } from "../../errors/sd-error.js";

describe("Mode B rejection guard", () => {
  it("accepts disabled SD and rejects enabled SD", () => {
    expect(() => assertModeBSdCompatible({ ingestion_mode: "MODE_B", sd_enabled: false })).not.toThrow();
    expect(() => assertModeBSdCompatible({ ingestion_mode: "MODE_B", sd_enabled: true })).toThrow(SdError);
  });
});
