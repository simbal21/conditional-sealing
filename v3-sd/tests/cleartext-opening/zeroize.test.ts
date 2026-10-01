// Regression tests for the SD cleartext zeroizer (security-audit-2026-05-14 TS-API-F-07).

import { describe, expect, it } from "vitest";
import { zeroizeSdBundleCleartext, zeroizeSdCleartext } from "../../src/cleartext-opening/zeroize.js";
import type { SdCleartextItem } from "../../src/types/sd-cleartext-item.js";

function makeItem(overrides: Partial<SdCleartextItem> = {}): SdCleartextItem {
  return {
    field_id: "0x" + "00".repeat(32) as `0x${string}`,
    field_path_hash: "0x" + "00".repeat(32) as `0x${string}`,
    field_path_label: "test_field",
    field_type_code: 1,
    value_encoding: "utf8",
    value: "secret_value",
    field_commitment: "0x1234" as `0x${string}`,
    policy_code: 1 as const,
    merkle_path: [
      { sibling: "0x" + "aa".repeat(32) as `0x${string}`, direction: 0 },
      { sibling: "0x" + "bb".repeat(32) as `0x${string}`, direction: 1 },
    ] as unknown as SdCleartextItem["merkle_path"],
    opening_mode: "cleartext_zk_opened",
    ...overrides,
  } as SdCleartextItem;
}

describe("zeroizeSdCleartext (TS-API-F-07)", () => {
  it("zeros a Uint8Array value field in place", () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const item = makeItem({ value: buf, value_encoding: "bytes" });
    const count = zeroizeSdCleartext([item]);
    expect(count).toBe(1);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it("replaces a string value with empty string", () => {
    const item = makeItem({ value: "supersecret-pii-string-do-not-leak" });
    zeroizeSdCleartext([item]);
    expect((item as { value: unknown }).value).toBe("");
  });

  it("replaces a number value with 0", () => {
    const item = makeItem({ value: 42 });
    zeroizeSdCleartext([item]);
    expect((item as { value: unknown }).value).toBe(0);
  });

  it("zeros nested Uint8Array inside an object value (best effort)", () => {
    const inner = new Uint8Array([9, 9, 9]);
    const item = makeItem({ value: { blob: inner, label: "x" } });
    zeroizeSdCleartext([item]);
    expect(Array.from(inner)).toEqual([0, 0, 0]);
  });

  it("empties the merkle_path array", () => {
    const item = makeItem();
    expect(item.merkle_path.length).toBe(2);
    zeroizeSdCleartext([item]);
    expect(item.merkle_path.length).toBe(0);
  });

  it("drops opening_proof when present", () => {
    const item = makeItem({
      opening_proof: { kind: "test", payload: "secret" } as unknown as SdCleartextItem["opening_proof"],
    });
    expect(item.opening_proof).toBeDefined();
    zeroizeSdCleartext([item]);
    expect(item.opening_proof).toBeUndefined();
  });

  it("processes multiple items and returns the count", () => {
    const items = [makeItem(), makeItem(), makeItem()];
    expect(zeroizeSdCleartext(items)).toBe(3);
    for (const item of items) {
      expect((item as { value: unknown }).value).toBe("");
    }
  });

  it("silently skips frozen items rather than throwing", () => {
    const item = Object.freeze(makeItem());
    const count = zeroizeSdCleartext([item]);
    expect(count).toBe(0); // skipped — frozen
  });

  it("zeroizeSdBundleCleartext zeros the bundle's cleartext array", () => {
    const items = [makeItem(), makeItem()];
    const bundle = { cleartext: items };
    expect(zeroizeSdBundleCleartext(bundle)).toBe(2);
    expect((bundle.cleartext[0] as { value: unknown }).value).toBe("");
    expect((bundle.cleartext[1] as { value: unknown }).value).toBe("");
  });

  it("zeroizeSdBundleCleartext handles bundles with no cleartext", () => {
    const bundle = {};
    expect(zeroizeSdBundleCleartext(bundle)).toBe(0);
  });
});
