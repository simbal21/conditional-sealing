import { describe, expect, it } from "vitest";
import { encodeFieldValue, FIELD_TYPE_CODE } from "../field-encoding.js";
import { deriveFieldId } from "../field-id-derivation.js";
import { canonicalizeSchema } from "../schema-canonicalization.js";

describe("field encoding + field_id", () => {
  it("encodes scalar field families and derives deterministic field ids", () => {
    expect(encodeFieldValue(true, FIELD_TYPE_CODE.bool).scalar).toBe(1n);
    expect(encodeFieldValue("DE", FIELD_TYPE_CODE.country_code).scalar).toBe(0x4445n);
    const schema = canonicalizeSchema({ fields: [{ path: " person.name ", type: "string" }] });
    const a = deriveFieldId({ schema_digest: schema.digest, normalized_field_path: "person.name", field_type: "string" });
    const b = deriveFieldId({ schema_digest: schema.digest, normalized_field_path: " person . name ", field_type: FIELD_TYPE_CODE.string });
    expect(Buffer.from(a.field_id).toString("hex")).toBe(Buffer.from(b.field_id).toString("hex"));
  });
});
