import { describe, expect, it } from "vitest";
import { redact } from "../log-sanitize.js";

describe("redaction log sanitizer", () => {
  it("replaces excluded values with opaque markers", () => {
    const result = redact({ raw_kyc: "sensitive" });
    expect(result.clean).toBe(false);
    expect(JSON.stringify(result.sanitized)).not.toContain("sensitive");
  });
});
