// Closure test — security-audit-2026-06-02 F-CRYPTO-1.
//
// VULNERABILITY (HEAD e87c108): `verifyPluginIntegrity` claimed to self-attest
// the running combiner binary against the on-chain PluginHashRegistry entry,
// but in production (no `CEALIS_COMBINER_BINARY_HASH` / `_SEED` env) the
// fallback `computeCanonicalBinaryHash(entry.binaryHashOrMeasurement)` returned
// `hexToBytes(entry.binaryHashOrMeasurement)` — the registry value itself —
// and then compared it against `hexToBytes(entry.binaryHashOrMeasurement)`:
// the registry value compared to ITSELF. The compare was a tautology that
// always passed for ANY registry value. There was no measurement of the
// actually-running code, so a combiner host running tampered code (e.g. one
// that exfiltrates the reconstructed DEK/plaintext) passed the check unchanged.
// Compounding: `assertNoBinaryHashOverridesInProduction` had ZERO callers, so
// the production override fail-fast never fired.
//
// FIX: the production fallback now MEASURES the actually-running combiner
// bundle (`measureRunningCombinerBundle`) and `verifyPluginIntegrity` binds
// that measurement to the registry entry. A registry `binaryHashOrMeasurement`
// that does NOT equal the measured running code is refused. The bootstrap
// guard is wired at module load.
//
// WHY THE TEST PROVES CLOSURE: assertion (1) below FAILS against the
// vulnerable code — under the tautology a registry entry whose
// `binaryHashOrMeasurement` is an arbitrary non-measured value (`0x77...`)
// passed `verifyPluginIntegrity` (compared the entry to itself); under the fix
// it is refused because the measured running bundle ≠ `0x77...`. The attack
// path is exactly "combiner host where the on-chain plugin-hash binding no
// longer matches the measured running code."

import { describe, expect, it } from "vitest";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
  combineAndDecrypt,
  measureRunningCombinerBundle,
  assertNoBinaryHashOverridesInProduction,
} from "../../src/index.js";
import { bytesToHex } from "../../src/combiner/jcs-canonicalize.js";
import { hex32, makeFixture, PLAINTEXT } from "./combiner-testkit.js";

describe("F-CRYPTO-1 — combiner binary self-attestation is a real measurement, not a tautology", () => {
  it("measures the running combiner bundle (deterministic, and NOT an echo of an arbitrary registry value)", () => {
    const m1 = measureRunningCombinerBundle();
    const m2 = measureRunningCombinerBundle();
    // Deterministic across calls — reproducible across hosts running the same code.
    expect(bytesToHex(m1)).toBe(bytesToHex(m2));
    expect(m1).toHaveLength(32);
    // The measurement is the hash of the running code, so it must NOT equal an
    // arbitrary chosen "registry" value. Under the OLD code the fallback simply
    // returned whatever was passed in, so this distinction did not exist.
    const arbitraryRegistryValue = hex32(0x77);
    expect(bytesToHex(m1)).not.toBe(arbitraryRegistryValue);
  });

  it("REFUSES a PluginHashRegistry entry whose binaryHashOrMeasurement ≠ the measured running code (the core attack path)", () => {
    // The fixture default sets `binaryHashOrMeasurement` to the live measured
    // digest, so the happy path decrypts. We now inject a registry entry whose
    // claimed binary hash is an arbitrary value that does NOT match the running
    // bundle — i.e. the on-chain binding points at a DIFFERENT (tampered or
    // simply-not-this) binary. The combiner must refuse.
    //
    // VULNERABLE CODE: passes (registry value `0x77...` was compared to itself).
    // FIXED CODE: refuses (measured running bundle ≠ `0x77...`).
    const base = makeFixture();
    const result = combineAndDecrypt({
      ...base,
      registrySnapshots: {
        ...base.registrySnapshots,
        commitSnapshot: {
          ...base.registrySnapshots.commitSnapshot,
          plugin: {
            ...base.registrySnapshots.commitSnapshot.plugin,
            binaryHashOrMeasurement: hex32(0x77),
          },
        },
      },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_COMBINER_BINARY_HASH_MISMATCH");
    }
  });

  it("ACCEPTS when the registry entry carries the genuine measured digest (no false positive)", () => {
    // Existence proof that the new binding is satisfiable by a deployment whose
    // build pipeline stamps the real measurement on-chain. The default fixture
    // already does this, so the happy path must continue to decrypt.
    const result = combineAndDecrypt(makeFixture());
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });

  it("assertNoBinaryHashOverridesInProduction is wired + refuses overrides under NODE_ENV=production", () => {
    // The bootstrap guard had ZERO callers in the vulnerable code (we now call
    // it at plugin-integrity module load). Behaviorally verify it actually
    // refuses an override in production, which is the defense the dangling
    // export documented but never delivered.
    expect(() =>
      assertNoBinaryHashOverridesInProduction({
        NODE_ENV: "production",
        CEALIS_COMBINER_BINARY_HASH: hex32(0x01),
      } as NodeJS.ProcessEnv),
    ).toThrow(CustodyError);
    expect(() =>
      assertNoBinaryHashOverridesInProduction({
        NODE_ENV: "production",
        CEALIS_COMBINER_BINARY_SEED: "attacker-seed",
      } as NodeJS.ProcessEnv),
    ).toThrow(CustodyError);
    // No override set in production ⇒ no throw (must self-attest against
    // the on-chain entry, which is allowed).
    expect(() =>
      assertNoBinaryHashOverridesInProduction({ NODE_ENV: "production" } as NodeJS.ProcessEnv),
    ).not.toThrow();
    // Non-production ⇒ no-op even with override set (tests legitimately use it).
    expect(() =>
      assertNoBinaryHashOverridesInProduction({
        NODE_ENV: "test",
        CEALIS_COMBINER_BINARY_HASH: hex32(0x01),
      } as NodeJS.ProcessEnv),
    ).not.toThrow();
  });
});
