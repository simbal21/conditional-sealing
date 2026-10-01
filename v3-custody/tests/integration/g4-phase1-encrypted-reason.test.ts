import { describe, expect, it } from "vitest";
import { encryptReasonBlob } from "../../g4-phase1/server/encrypted-reason.js";

describe("G4 Phase 1 encrypted reason mode", () => {
  it("does not expose plaintext in encrypted blob or JSON output for 0x02/0x03 style reasons", () => {
    const secretText = "subject requested erasure under sensitive legal basis";
    const plaintext = new TextEncoder().encode(secretText);
    const key = new Uint8Array(32).fill(7);
    const iv = new Uint8Array(12).fill(1);
    const encrypted = encryptReasonBlob(plaintext, key, iv);

    expect(new TextDecoder().decode(encrypted.encryptedReasonBlob)).not.toContain(secretText);
    expect(JSON.stringify(encrypted)).not.toContain(secretText);
    expect(plaintext.every((byte) => byte === 0)).toBe(true);
  });
});
