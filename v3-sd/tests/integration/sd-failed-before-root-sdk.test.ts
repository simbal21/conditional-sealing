import { describe, expect, it } from "vitest";
import { verifySdRootBinding, SD_MERKLE_ROOT_ZERO } from "../../src/merkle/binding.js";
import { b32 } from "./helpers.js";

describe("App. J §J.1 SDK binding modes", () => {
  it("covers sd_disabled, sd_enabled, and sd_failed_before_root", () => {
    const root = b32("root");
    expect(verifySdRootBinding({ bundle_root: SD_MERKLE_ROOT_ZERO, commit_aad_root: SD_MERKLE_ROOT_ZERO, pda_sd_enabled: false, bundle_status: "not_configured" })).toBe("sd_disabled");
    expect(verifySdRootBinding({ bundle_root: root, commit_aad_root: root, pda_sd_enabled: true, bundle_status: "complete" })).toBe("sd_enabled");
    expect(verifySdRootBinding({ bundle_root: SD_MERKLE_ROOT_ZERO, commit_aad_root: SD_MERKLE_ROOT_ZERO, pda_sd_enabled: true, bundle_status: "failed" })).toBe("sd_failed_before_root");
  });
});

