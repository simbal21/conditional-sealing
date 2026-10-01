// Foundation test — A13: no DB / queue / Redis deps (greenfield, TEE-side).
//
// M6 is TEE-side ephemerality by design. Unlike M5, M6 has no Postgres /
// Redis / BullMQ surface. The on-chain revocation worker (Phase D) is a
// stateless viem listener that consumes `ShredFinalized` events from M2
// and calls `revokeDisclosure` — state lives on-chain.
//
// This foundation test pins the dependency surface.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_PATH = resolve(__dirname, "..", "..", "package.json");

describe("@cealis/v3-sd dependency surface (A13)", () => {
  it("MUST NOT depend on drizzle-orm / pg / postgres / bullmq / ioredis", () => {
    const pkg = JSON.parse(readFileSync(PKG_PATH, "utf-8"));
    const all = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
      ...(pkg.peerDependencies ?? {}),
    };
    const forbidden = ["drizzle-orm", "pg", "postgres", "bullmq", "ioredis"];
    for (const f of forbidden) {
      expect(Object.keys(all)).not.toContain(f);
    }
  });

  it("ships @cealis/v3-crypto + @noble/* + circomlibjs + snarkjs + viem + canonicalize + pino", () => {
    const pkg = JSON.parse(readFileSync(PKG_PATH, "utf-8"));
    const deps = pkg.dependencies ?? {};
    expect(deps).toHaveProperty("@cealis/v3-crypto");
    expect(deps).toHaveProperty("@noble/hashes");
    expect(deps).toHaveProperty("@noble/curves");
    expect(deps).toHaveProperty("circomlibjs");
    expect(deps).toHaveProperty("snarkjs");
    expect(deps).toHaveProperty("viem");
    expect(deps).toHaveProperty("canonicalize");
    expect(deps).toHaveProperty("pino");
  });

  it("MUST NOT depend on forbidden Cealis workspace packages (custody / api / configurator / verify-sdk)", () => {
    const pkg = JSON.parse(readFileSync(PKG_PATH, "utf-8"));
    const all = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
      ...(pkg.peerDependencies ?? {}),
    };
    expect(Object.keys(all)).not.toContain("@cealis/v3-custody");
    expect(Object.keys(all)).not.toContain("@cealis/v3-api");
    expect(Object.keys(all)).not.toContain("@cealis/v3-configurator");
    expect(Object.keys(all)).not.toContain("@cealis/verify-sdk");
  });
});
