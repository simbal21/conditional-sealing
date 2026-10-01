import { describe, expect, it } from "vitest";
import { findEvent, loadM2Artifact } from "../../src/m2-imports.js";

describe("DisclosureRevoked privacy default", () => {
  it("does not emit subject_commitment_v3 in topics or data", () => {
    const event = findEvent(loadM2Artifact("DisclosureRevocationRegistry"), "DisclosureRevoked");
    const names = event.inputs.map((input) => input.name);
    expect(names).toEqual(["disclosureId", "authorizationId", "reasonCode", "evidenceRef"]);
    expect(names).not.toContain("subject_commitment_v3");
    expect(event.inputs.filter((input) => input.indexed).map((input) => input.name)).toEqual(["disclosureId", "authorizationId"]);
  });
});

