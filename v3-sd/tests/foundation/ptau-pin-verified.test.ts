// Foundation test — Phase A ptau-pin baseline.

import { describe, it, expect } from "vitest";
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PIN_PATH = resolve(__dirname, "..", "..", "setup", "ptau-pin.json");

describe("Phase A ptau pin file", () => {
  it("setup/ptau-pin.json exists", () => {
    expect(statSync(PIN_PATH).isFile()).toBe(true);
  });

  it("ptau-pin.json declares dev-mode warning + M7 deferral", () => {
    const pin = JSON.parse(readFileSync(PIN_PATH, "utf-8"));
    expect(pin.ceremony_dev_mode_warning).toContain("DEV-MODE ONLY");
    expect(pin.deferred_to).toBe("M7");
  });

  it("ptau-pin.json declares at least one download with URL + sha256 slot", () => {
    const pin = JSON.parse(readFileSync(PIN_PATH, "utf-8"));
    expect(typeof pin.downloads).toBe("object");
    const keys = Object.keys(pin.downloads);
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) {
      const entry = pin.downloads[k];
      expect(entry.url).toMatch(/^https?:\/\//);
      expect(typeof entry.sha256).toBe("string");
    }
  });

  it("selected_ptau_default points at a registered download", () => {
    const pin = JSON.parse(readFileSync(PIN_PATH, "utf-8"));
    expect(typeof pin.selected_ptau_default).toBe("string");
    expect(Object.keys(pin.downloads)).toContain(pin.selected_ptau_default);
  });
});
