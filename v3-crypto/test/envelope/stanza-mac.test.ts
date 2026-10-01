import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  buildStanzaMacInput,
  computeStanzaMac,
  stanzaMacEquals,
  STANZA_BINDING_TAGS,
} from "../../src/envelope/stanza-mac.js";
import type { Hex32 } from "../../src/tags.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "stanza-mac.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  fixture: { plugin_version_digest: string };
  vectors: Array<{
    name: string;
    stanza_index: number;
    binding_tag: string;
    binding_tag_symbol: string;
    stanza_mac: string;
  }>;
};

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const PVD = hexBytes(golden.fixture.plugin_version_digest);

describe("stanza_mac — §6.1.4 keyless keccak", () => {
  it("mac_input is 68 bytes (4 + 32 + 32)", () => {
    const input = buildStanzaMacInput(0, STANZA_BINDING_TAGS.LIT_ACC, PVD);
    expect(input.length).toBe(68);
  });

  it("stanza_mac is 32 bytes", () => {
    const mac = computeStanzaMac(0, STANZA_BINDING_TAGS.LIT_ACC, PVD);
    expect(mac.length).toBe(32);
  });

  it("matches all 5 golden vectors", () => {
    for (const v of golden.vectors) {
      const mac = computeStanzaMac(v.stanza_index, v.binding_tag as Hex32, PVD);
      expect(bytesToHex(mac)).toBe(v.stanza_mac);
    }
  });

  it("changing stanza_index changes the MAC", () => {
    const mac0 = computeStanzaMac(0, STANZA_BINDING_TAGS.LIT_ACC, PVD);
    const mac1 = computeStanzaMac(1, STANZA_BINDING_TAGS.LIT_ACC, PVD);
    expect(bytesToHex(mac0)).not.toBe(bytesToHex(mac1));
  });

  it("changing binding_tag changes the MAC", () => {
    const macLit = computeStanzaMac(0, STANZA_BINDING_TAGS.LIT_ACC, PVD);
    const macG4 = computeStanzaMac(0, STANZA_BINDING_TAGS.G4_AUTHORITY, PVD);
    expect(bytesToHex(macLit)).not.toBe(bytesToHex(macG4));
  });

  it("changing plugin_version_digest changes the MAC", () => {
    const macA = computeStanzaMac(0, STANZA_BINDING_TAGS.LIT_ACC, PVD);
    const otherPVD = new Uint8Array(32).fill(0xab);
    const macB = computeStanzaMac(0, STANZA_BINDING_TAGS.LIT_ACC, otherPVD);
    expect(bytesToHex(macA)).not.toBe(bytesToHex(macB));
  });

  it("rejects wrong-length plugin_version_digest", () => {
    expect(() => buildStanzaMacInput(0, STANZA_BINDING_TAGS.LIT_ACC, new Uint8Array(31))).toThrow();
  });

  it("rejects out-of-range stanza_index", () => {
    expect(() => buildStanzaMacInput(-1, STANZA_BINDING_TAGS.LIT_ACC, PVD)).toThrow();
    expect(() =>
      buildStanzaMacInput(0x1_0000_0000, STANZA_BINDING_TAGS.LIT_ACC, PVD),
    ).toThrow();
  });

  it("stanzaMacEquals is true for equal MACs and false for different", () => {
    const a = new Uint8Array(32).fill(0x42);
    const b = new Uint8Array(32).fill(0x42);
    const c = new Uint8Array(32).fill(0x43);
    expect(stanzaMacEquals(a, b)).toBe(true);
    expect(stanzaMacEquals(a, c)).toBe(false);
  });

  it("stanzaMacEquals throws on length mismatch", () => {
    expect(() => stanzaMacEquals(new Uint8Array(31), new Uint8Array(32))).toThrow();
  });
});
