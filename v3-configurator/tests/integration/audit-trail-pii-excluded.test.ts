import { describe, expect, it } from "vitest";
import { redact } from "../../src/redaction/index.js";
import { PII_EXCLUSION_PATTERNS } from "../../src/types/audit-trail.js";

describe("§1.4 audit trail exclusion redaction", () => {
  it("redacts every configured excluded marker at runtime", () => {
    for (const pattern of PII_EXCLUSION_PATTERNS) {
      const result = redact({ nested: { [pattern]: "must-not-survive" } });
      expect(result.clean).toBe(false);
      expect(result.patterns_matched).toContain(pattern);
      expect(JSON.stringify(result.sanitized)).not.toContain("must-not-survive");
    }
  });
});
