// Foundation test — M2 ABI smoke.
//
// Asserts:
//   1. Both Foundry artifact JSONs exist on disk at expected paths.
//   2. Every expected function/event is present in the ABI.
//   3. `DisclosureRevoked` event indexes ONLY `disclosureId + authorizationId`
//      (privacy default §App.I.11 line 2394 — `subject_commitment_v3` absent).
//   4. `revokeDisclosure` signature is (bytes32, uint8, bytes32).

import { describe, it, expect } from "vitest";
import {
  loadM2Artifact,
  findFunction,
  findEvent,
  EXPECTED_DISCLOSURE_REGISTRY_FUNCTIONS,
  EXPECTED_DISCLOSURE_REGISTRY_EVENTS,
  EXPECTED_REVOCATION_REGISTRY_FUNCTIONS,
  EXPECTED_REVOCATION_REGISTRY_EVENTS,
  M2_ARTIFACT_PATHS,
} from "../../src/m2-imports.js";
import { statSync } from "node:fs";

describe("M2 ABI facade — smoke + privacy invariants", () => {
  it("both Foundry artifact JSONs exist on disk", () => {
    expect(statSync(M2_ARTIFACT_PATHS.DisclosureRegistry).isFile()).toBe(true);
    expect(statSync(M2_ARTIFACT_PATHS.DisclosureRevocationRegistry).isFile()).toBe(true);
  });

  it("DisclosureRegistry ABI contains every expected function", () => {
    const artifact = loadM2Artifact("DisclosureRegistry");
    for (const name of EXPECTED_DISCLOSURE_REGISTRY_FUNCTIONS) {
      const fn = findFunction(artifact, name);
      expect(fn.name).toBe(name);
    }
  });

  it("DisclosureRegistry ABI contains every expected event (initial M2 set)", () => {
    const artifact = loadM2Artifact("DisclosureRegistry");
    for (const name of EXPECTED_DISCLOSURE_REGISTRY_EVENTS) {
      const ev = findEvent(artifact, name);
      expect(ev.name).toBe(name);
    }
  });

  it("DisclosureRevocationRegistry ABI contains every expected function", () => {
    const artifact = loadM2Artifact("DisclosureRevocationRegistry");
    for (const name of EXPECTED_REVOCATION_REGISTRY_FUNCTIONS) {
      const fn = findFunction(artifact, name);
      expect(fn.name).toBe(name);
    }
  });

  it("DisclosureRevocationRegistry ABI contains every expected event", () => {
    const artifact = loadM2Artifact("DisclosureRevocationRegistry");
    for (const name of EXPECTED_REVOCATION_REGISTRY_EVENTS) {
      const ev = findEvent(artifact, name);
      expect(ev.name).toBe(name);
    }
  });

  it("PRIVACY: DisclosureRevoked event has exactly 4 inputs and indexes ONLY disclosureId + authorizationId (§App.I.11 line 2394)", () => {
    const artifact = loadM2Artifact("DisclosureRevocationRegistry");
    const ev = findEvent(artifact, "DisclosureRevoked");

    expect(ev.inputs.length).toBe(4);

    // Expected: disclosureId (indexed), authorizationId (indexed), reasonCode (not indexed), evidenceRef (not indexed)
    const byName = Object.fromEntries(ev.inputs.map((i) => [i.name, i]));

    expect(byName.disclosureId).toBeDefined();
    expect(byName.disclosureId?.indexed).toBe(true);
    expect(byName.disclosureId?.type).toBe("bytes32");

    expect(byName.authorizationId).toBeDefined();
    expect(byName.authorizationId?.indexed).toBe(true);
    expect(byName.authorizationId?.type).toBe("bytes32");

    expect(byName.reasonCode).toBeDefined();
    expect(byName.reasonCode?.indexed).toBeFalsy();
    expect(byName.reasonCode?.type).toBe("uint8");

    expect(byName.evidenceRef).toBeDefined();
    expect(byName.evidenceRef?.indexed).toBeFalsy();
    expect(byName.evidenceRef?.type).toBe("bytes32");

    // subject_commitment_v3 MUST be ABSENT from the event input set.
    expect(byName.subject_commitment_v3).toBeUndefined();
    for (const inp of ev.inputs) {
      expect(inp.name).not.toBe("subject_commitment_v3");
    }
  });

  it("revokeDisclosure has signature (bytes32, uint8, bytes32)", () => {
    const artifact = loadM2Artifact("DisclosureRevocationRegistry");
    const fn = findFunction(artifact, "revokeDisclosure");
    expect(fn.inputs.length).toBe(3);
    expect(fn.inputs[0]?.type).toBe("bytes32"); // disclosureId
    expect(fn.inputs[1]?.type).toBe("uint8");   // reasonCode (6-row enum per §11.5)
    expect(fn.inputs[2]?.type).toBe("bytes32"); // evidenceRef
  });
});
