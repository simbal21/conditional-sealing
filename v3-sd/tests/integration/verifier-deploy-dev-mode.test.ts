import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CONTRACTS_DIR = resolve(__dirname, "..", "..", "contracts");

describe("dev-mode verifier deploy surface", () => {
  it("ships four per-predicate verifier contracts and the dev deploy script", () => {
    const files = [
      "PlonkVerifierEquality.sol",
      "PlonkVerifierNonEquality.sol",
      "PlonkVerifierRange.sol",
      "PlonkVerifierSetMembership.sol",
    ];

    for (const file of files) {
      const source = readFileSync(resolve(CONTRACTS_DIR, file), "utf-8");
      expect(source).toContain("function verifyProof(bytes calldata proof, uint256[] calldata publicInputs)");
      expect(source).not.toContain("hardhat/console.sol");
    }

    const deployScript = readFileSync(resolve(__dirname, "..", "..", "script", "Deploy.s.sol"), "utf-8");
    expect(deployScript).toContain("registerVerifierContract");
    expect(deployScript).toContain("PlonkVerifierSetMembership");
  });
});
