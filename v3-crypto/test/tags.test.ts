import { describe, it, expect } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { TAG_DIGESTS, TAG_LABELS, type TagSymbol } from "../src/tags.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "fixtures", "tag-digests.golden.json");
const goldenJson = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  tags: Array<{ symbol: string; label: string; digest: string }>;
};

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe("TAG_*_V3 — 30 keccak digests per S2-1 §2.3", () => {
  it("golden file lists exactly 30 tags", () => {
    expect(goldenJson.tags).toHaveLength(30);
  });

  it("every src/tags.ts digest matches the golden file digest", () => {
    for (const row of goldenJson.tags) {
      const sym = row.symbol as TagSymbol;
      expect(TAG_DIGESTS[sym]).toBe(row.digest);
    }
  });

  it("every label in src/tags.ts matches the golden file label", () => {
    for (const row of goldenJson.tags) {
      const sym = row.symbol as TagSymbol;
      expect(TAG_LABELS[sym]).toBe(row.label);
    }
  });

  it("every TAG digest is keccak256(bytes(label)) per §2.1 derivation rule", () => {
    for (const row of goldenJson.tags) {
      const sym = row.symbol as TagSymbol;
      const labelBytes = new TextEncoder().encode(TAG_LABELS[sym]);
      const computed = keccak_256(labelBytes);
      expect(computed).toEqual(hexBytes(TAG_DIGESTS[sym]));
    }
  });

  it("three deviation labels are spec-locked (not symbol-derived)", () => {
    expect(TAG_LABELS.TAG_COMMIT_V3).toBe("CEALIS_V3_COMMITMENT_HASH_V3");
    expect(TAG_LABELS.TAG_AUTHID_V3).toBe("CEALIS_V3_AUTH_ID_V3");
    expect(TAG_LABELS.TAG_SUBJECT_V3).toBe("CEALIS_V3_SUBJECT_V3");
  });
});
