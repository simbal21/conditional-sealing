import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Hex32 } from "@cealis/v3-crypto";
import { CUSTODY_ERROR_CODES } from "../../src/errors.js";
import { fetchAndVerifyLitAssignment } from "../../src/g2-lit/assignment-fetch.js";
import { hexToBytes } from "../../src/g2-lit/acc-canonicalize.js";
import type { LitAssignmentRecord } from "../../src/types/registries.js";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "vendor", "lit");
const sigma = JSON.parse(readFileSync(join(fixtureDir, "sigma-vector.json"), "utf8")) as { authorizationId: Hex32 };
const fixture = JSON.parse(readFileSync(join(fixtureDir, "assignment-fixture.json"), "utf8")) as { assignedTeeId: Hex32; assignmentBlock: string; assignedTeePubkey: string; sourceGovernanceDigest: Hex32 };

describe("G2 Lit assignment mismatch", () => {
  it("rejects quote tee id that differs from LitV3Assignment", async () => {
    const record: LitAssignmentRecord = {
      authorizationId: sigma.authorizationId,
      assignedTeeId: fixture.assignedTeeId,
      assignmentBlock: BigInt(fixture.assignmentBlock),
      assignedTeePubkey: hexToBytes(fixture.assignedTeePubkey),
      sourceGovernanceDigest: fixture.sourceGovernanceDigest,
    };
    await expect(
      fetchAndVerifyLitAssignment({
        registryReader: { async getLitAssignmentAt() { return record; } },
        authorizationId: sigma.authorizationId,
        authorizationBlock: 12_345n,
        assignedTeeIdFromQuote: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      }),
    ).rejects.toMatchObject({ code: CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH });
  });
});
