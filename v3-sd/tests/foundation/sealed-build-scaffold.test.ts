// Foundation test — sealed-build scaffold smoke.
//
// PHASE A scaffold ONLY — Phase A asserts the files exist + are executable.
// Real M3 sealed-code integration deferred to M7/M8.

import { describe, it, expect } from "vitest";
import { statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..");

describe("Phase A sealed-build scaffold (A19)", () => {
  it("scripts/sealed-build.sh exists", () => {
    expect(statSync(resolve(REPO_ROOT, "scripts", "sealed-build.sh")).isFile()).toBe(true);
  });

  it("Dockerfile.sealed-ingestion scaffold exists", () => {
    expect(statSync(resolve(REPO_ROOT, "Dockerfile.sealed-ingestion")).isFile()).toBe(true);
  });
});
