import { describe, it, expect } from "vitest";
import {
  loadArtifact,
  getRevealAuthorizedEvent,
  getConditionEngineAbi,
  REVEAL_AUTHORIZED_EXPECTED_INPUTS,
  ARTIFACT_PATHS,
} from "../../src/m2-imports.js";
import { existsSync } from "node:fs";

describe("M2 ABI smoke (Foundry artifact loader)", () => {
  it("ConditionEngine artifact exists on disk at expected path", () => {
    expect(existsSync(ARTIFACT_PATHS.ConditionEngine)).toBe(true);
  });

  it("loadArtifact returns parsed Foundry JSON with abi[]", () => {
    const art = loadArtifact("ConditionEngine");
    expect(Array.isArray(art.abi)).toBe(true);
    expect(art.abi.length).toBeGreaterThan(0);
  });

  it("RevealAuthorized event found with 7 inputs", () => {
    const art = loadArtifact("ConditionEngine");
    const ev = getRevealAuthorizedEvent(art);
    expect(ev.name).toBe("RevealAuthorized");
    expect(ev.type).toBe("event");
    expect(ev.inputs.length).toBe(7);
  });

  it("RevealAuthorized 7 inputs match expected name + type + indexed", () => {
    const art = loadArtifact("ConditionEngine");
    const ev = getRevealAuthorizedEvent(art);
    for (let i = 0; i < REVEAL_AUTHORIZED_EXPECTED_INPUTS.length; i++) {
      const expected = REVEAL_AUTHORIZED_EXPECTED_INPUTS[i]!;
      const actual = ev.inputs[i]!;
      expect(actual.name, `input[${i}].name`).toBe(expected.name);
      expect(actual.type, `input[${i}].type`).toBe(expected.type);
      expect(Boolean(actual.indexed), `input[${i}].indexed`).toBe(expected.indexed);
    }
  });

  it("3 indexed topics + 4 unindexed (= 4 LOG topics total, 7 ABI inputs)", () => {
    const art = loadArtifact("ConditionEngine");
    const ev = getRevealAuthorizedEvent(art);
    const indexedCount = ev.inputs.filter((i) => i.indexed).length;
    expect(indexedCount).toBe(3);
    expect(ev.inputs.length - indexedCount).toBe(4);
  });

  it("getConditionEngineAbi convenience export works", () => {
    const abi = getConditionEngineAbi();
    expect(Array.isArray(abi)).toBe(true);
    expect(abi.length).toBeGreaterThan(0);
  });
});
