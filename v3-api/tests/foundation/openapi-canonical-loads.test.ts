import { describe, it, expect } from "vitest";
import {
  loadCanonicalOpenApi,
  extractOperationIds,
  assertCanonicalOperationIds,
  RouteRegistry,
} from "../../src/openapi/scaffold.js";
import { OPERATION_IDS } from "../../src/types/operation-ids.js";

describe("OpenAPI canonical doc loads (S2-5 §1.7)", () => {
  it("parses canonical.yaml at boot", () => {
    const doc = loadCanonicalOpenApi();
    expect(doc.openapi).toBe("3.1.0");
    expect(doc.info?.title).toContain("Cealis S2-5");
    expect(doc.paths).toBeDefined();
  });

  it("contains exactly 29 operationIds", () => {
    const doc = loadCanonicalOpenApi();
    const ids = extractOperationIds(doc);
    expect(ids.size).toBe(29);
  });

  it("operationId set matches OPERATION_IDS (no drift)", () => {
    // Wraps assertCanonicalOperationIds — throws on drift.
    expect(() => assertCanonicalOperationIds()).not.toThrow();
  });

  it("every code-level OPERATION_IDS entry appears in canonical YAML", () => {
    const doc = loadCanonicalOpenApi();
    const yamlIds = extractOperationIds(doc);
    for (const id of OPERATION_IDS) {
      expect(yamlIds.has(id), `missing from canonical.yaml: ${id}`).toBe(true);
    }
  });
});

describe("RouteRegistry", () => {
  it("registers and reports coverage", () => {
    const reg = new RouteRegistry();
    expect(reg.list().length).toBe(0);
    reg.register({
      operationId: "getG4EndpointAttestation",
      method: "GET",
      url: "/v1/g4/attestation",
    });
    expect(reg.has("getG4EndpointAttestation")).toBe(true);
    expect(reg.list().length).toBe(1);
  });

  it("assertCoverage throws if any locked operationId missing", () => {
    const reg = new RouteRegistry();
    reg.register({
      operationId: "getG4EndpointAttestation",
      method: "GET",
      url: "/v1/g4/attestation",
    });
    expect(() => reg.assertCoverage()).toThrow(/missing/);
  });
});
