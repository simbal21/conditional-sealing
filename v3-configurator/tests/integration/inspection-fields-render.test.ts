import { describe, expect, it } from "vitest";
import { kycLendingSubmittedPda } from "../../fixtures/app-a/index.js";
import { emitPDA } from "../../src/pda/emit.js";
import { serializeInspection } from "../../src/pda/inspection.js";
import { PARTNER_INSPECTION_PRIMITIVE_FIELDS } from "../../src/types/partner-inspection.js";

describe("§7.3 partner inspection rendering", () => {
  it("renders every 28-field primitive", async () => {
    const artifact = await emitPDA(kycLendingSubmittedPda);
    const rendered = serializeInspection(artifact.inspection);

    expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS).toHaveLength(28);
    for (const field of PARTNER_INSPECTION_PRIMITIVE_FIELDS) {
      expect(rendered[field]).not.toBeUndefined();
    }
  });
});
