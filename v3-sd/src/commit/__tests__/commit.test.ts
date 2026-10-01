import { describe, expect, it } from "vitest";
import { buildFieldCommitmentFromBytes } from "../construction.js";
import { deriveSdFieldSalt, deriveSdMasterSalt, deriveSdSaltContextDigest } from "../salt-derivation.js";
import { b32 } from "../../../tests/integration/helpers.js";
import { scalarToBytes32 } from "../../encoding/field-encoding.js";

describe("commitment + salt derivation", () => {
  it("derives a salt with rejection metadata and builds a BN254 commitment", () => {
    const ctx = deriveSdSaltContextDigest({
      authorizationId: b32("auth"),
      pda_root: b32("pda"),
      schema_digest: b32("schema"),
      partner_id: b32("partner"),
      sd_plan_digest: b32("plan"),
    });
    const master = deriveSdMasterSalt(b32("dek"), ctx);
    const salt = deriveSdFieldSalt({ sd_master_salt: master, authorizationId: b32("auth"), field_id: b32("field"), field_index: 0 });
    const commitment = buildFieldCommitmentFromBytes({
      authorizationId: b32("auth"),
      field_id: b32("field"),
      field_salt_bytes: salt.salt_bytes,
      value_scalar_encoded_bytes: scalarToBytes32(7n),
    });
    expect(commitment).toBeGreaterThan(0n);
    expect(salt.retry_count).toBeGreaterThanOrEqual(0);
  });
});
