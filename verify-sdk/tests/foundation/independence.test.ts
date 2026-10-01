import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Independence is a NORMATIVE security property (S2-5 §4.7 + §9.1).
// This test asserts package.json declares zero forbidden dependencies.

describe("verify-sdk independence (package.json)", () => {
  const pkgPath = resolve(__dirname, "../../package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));

  const FORBIDDEN_DEPS = [
    "axios",
    "node-fetch",
    "got",
    "undici", // outside of viem's built-in usage; viem is whitelisted
    "@cealis/v3-api",
    "@cealis/v3-custody",
    "fastify",
    "drizzle-orm",
    "pg",
    "postgres",
    "bullmq",
    "ioredis",
  ];

  const ALLOWED_DEPS = [
    "@cealis/v3-crypto",
    "@noble/hashes",
    "canonicalize",
    "viem",
  ];

  it("declares zero Cealis-network deps and zero non-verification runtime deps", () => {
    const deps = Object.keys(pkg.dependencies ?? {});
    for (const forbidden of FORBIDDEN_DEPS) {
      expect(deps, `forbidden runtime dep present: ${forbidden}`).not.toContain(forbidden);
    }
  });

  it("only allows verification primitives + chain reader (viem)", () => {
    const deps = Object.keys(pkg.dependencies ?? {});
    for (const dep of deps) {
      expect(ALLOWED_DEPS, `unexpected runtime dep: ${dep}`).toContain(dep);
    }
  });

  it("declares no devDependencies that imply Cealis API integration", () => {
    const devDeps = Object.keys(pkg.devDependencies ?? {});
    for (const forbidden of FORBIDDEN_DEPS) {
      expect(devDeps, `forbidden dev dep present: ${forbidden}`).not.toContain(forbidden);
    }
  });
});
