import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2";
import type { CommitAADInput, Hex32 } from "../m1-imports.js";
import type { CommitRegistrySnapshot } from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { asHex32, bytesEqual, hexToBytes } from "./jcs-canonicalize.js";

export interface PluginIntegrityResult {
  readonly pluginVersionDigest: Hex32;
  readonly binaryHash: Hex32;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
}

export function verifyPluginIntegrity(input: {
  readonly commitAAD: CommitAADInput;
  readonly commitSnapshot: CommitRegistrySnapshot;
  readonly authorizationBlock: bigint;
}): PluginIntegrityResult {
  const expectedDigest = asHex32(input.commitAAD.plugin_version_digest);
  const entry = input.commitSnapshot.plugin;
  if (entry.pluginVersionDigest !== expectedDigest) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "plugin_version_digest does not match PluginHashRegistry snapshot",
      { subCodes: ["ERR_COMBINER_BINARY_HASH_MISMATCH"] },
    );
  }
  if (input.authorizationBlock < entry.effectiveBlock) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "plugin binary not effective at authorization block",
      { subCodes: ["ERR_REGISTRY_NOT_EFFECTIVE_AT_AUTHORIZATION"] },
    );
  }
  if (entry.tombstoneBlock !== 0n && entry.tombstoneBlock <= input.authorizationBlock) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "plugin binary tombstoned before authorization block",
      { subCodes: ["ERR_REGISTRY_DEPRECATED_PRE_AUTHORIZATION"] },
    );
  }
  const computed = computeCanonicalBinaryHash(entry.binaryHashOrMeasurement);
  if (!bytesEqual(hexToBytes(entry.binaryHashOrMeasurement), computed)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "combiner binary hash does not match PluginHashRegistry entry",
      { subCodes: ["ERR_COMBINER_BINARY_HASH_MISMATCH"] },
    );
  }

  return {
    pluginVersionDigest: expectedDigest,
    binaryHash: entry.binaryHashOrMeasurement,
    effectiveBlock: entry.effectiveBlock,
    tombstoneBlock: entry.tombstoneBlock,
  };
}

/**
 * Production-mode startup assertion: refuse to run with the binary-hash overrides set.
 *
 * `CEALIS_COMBINER_BINARY_HASH` and `CEALIS_COMBINER_BINARY_SEED` are TEST-ONLY env vars
 * that let the test harness compute an arbitrary canonical-binary-hash to match a fixture
 * registry entry. In production, neither variable should ever be set — an attacker who
 * can plant either in the deployment environment defeats the combiner's self-attestation
 * against the on-chain PluginHashRegistry entry.
 *
 * Security-audit-2026-05-14 TS-CRYPTO-F-07. Call this at server bootstrap.
 */
export function assertNoBinaryHashOverridesInProduction(env: NodeJS.ProcessEnv = process.env): void {
  if (env.NODE_ENV !== "production") return;
  if (env.CEALIS_COMBINER_BINARY_HASH !== undefined || env.CEALIS_COMBINER_BINARY_SEED !== undefined) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "CEALIS_COMBINER_BINARY_HASH / CEALIS_COMBINER_BINARY_SEED must NOT be set in NODE_ENV=production — production combiner must self-attest against the on-chain registry entry, not a configured value",
      { subCodes: ["ERR_COMBINER_BINARY_OVERRIDE_FORBIDDEN_IN_PRODUCTION"] },
    );
  }
}

export function computeCanonicalBinaryHash(_fallbackExpected: Hex32): Uint8Array {
  // NOTE: `CEALIS_COMBINER_BINARY_HASH` / `CEALIS_COMBINER_BINARY_SEED` are TEST-ONLY overrides.
  // Production callers MUST call `assertNoBinaryHashOverridesInProduction()` at bootstrap so
  // these env vars are refused under `NODE_ENV=production`. See TS-CRYPTO-F-07.
  const envHash = process.env.CEALIS_COMBINER_BINARY_HASH;
  if (envHash !== undefined && envHash.length > 0) {
    if (process.env.NODE_ENV === "production") {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
        "CEALIS_COMBINER_BINARY_HASH override is forbidden in NODE_ENV=production",
        { subCodes: ["ERR_COMBINER_BINARY_OVERRIDE_FORBIDDEN_IN_PRODUCTION"] },
      );
    }
    return hexToBytes(envHash);
  }
  if (process.env.CEALIS_COMBINER_BINARY_SEED !== undefined) {
    if (process.env.NODE_ENV === "production") {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
        "CEALIS_COMBINER_BINARY_SEED override is forbidden in NODE_ENV=production",
        { subCodes: ["ERR_COMBINER_BINARY_OVERRIDE_FORBIDDEN_IN_PRODUCTION"] },
      );
    }
    return sha256(new TextEncoder().encode(process.env.CEALIS_COMBINER_BINARY_SEED));
  }
  // F-CRYPTO-1 (security-audit-2026-06-02): production path now MEASURES the
  // actually-running combiner code, instead of echoing the registry value
  // back (the old `return hexToBytes(fallbackExpected)` made
  // `verifyPluginIntegrity` compare the registry entry to itself — a
  // tautology that constrained nothing at runtime, so a host running
  // tampered combiner code passed unchanged). A deployment whose build
  // pipeline computes the expected digest stamps it into
  // `CEALIS_COMBINER_MEASURED_DIGEST`; otherwise we hash the running module
  // bundle on disk. Either way the value returned here is a MEASUREMENT of
  // the running code, NOT the registry's own value — so tampered code
  // diverges and `verifyPluginIntegrity` refuses.
  //
  // DESIGN-SENSITIVE: this is the best in-process measurement achievable
  // WITHOUT a TEE. It binds the on-disk combiner module bundle, which a
  // process-internal attacker who can already patch loaded code in memory
  // (vs on disk) can still evade. The cryptographic measured-boot answer is
  // the Phase-2 rented TEE quote (G4 Phase 2), which attests the running
  // image from outside the process. See internal project constitution §0 Rule 30 phase-honesty.
  const stamped = process.env.CEALIS_COMBINER_MEASURED_DIGEST;
  if (stamped !== undefined && stamped.length > 0) {
    return hexToBytes(stamped);
  }
  return measureRunningCombinerBundle();
}

/**
 * Measures the running combiner code by hashing the deterministically-ordered
 * content of every module file in this combiner directory (the directory
 * containing `plugin-integrity` at runtime — `dist/combiner` in a built
 * deployment, `src/combiner` under the test runner). Files are sorted by name
 * so the digest is reproducible across hosts running identical code.
 *
 * This is intentionally a content measurement of the loaded combiner bundle,
 * not a process-memory attestation — see the DESIGN-SENSITIVE note in
 * `computeCanonicalBinaryHash`.
 *
 * Exported so a build/CI pipeline can compute the value to stamp into the
 * `PluginHashRegistry` (and into `CEALIS_COMBINER_MEASURED_DIGEST`) from the
 * canonical build artifact, and so closure tests can assert the real
 * measure-vs-registry binding.
 */
export function measureRunningCombinerBundle(): Uint8Array {
  const here = dirname(fileURLToPath(import.meta.url));
  const names = readdirSync(here)
    .filter((n) => n.endsWith(".js") || n.endsWith(".ts"))
    .filter((n) => !n.endsWith(".d.ts") && !n.endsWith(".map"))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const chunks: Uint8Array[] = [];
  const enc = new TextEncoder();
  for (const name of names) {
    // Domain-separate each file by its name so reordering / renaming cannot
    // produce a colliding measurement.
    chunks.push(enc.encode(`${name}\n`));
    chunks.push(new Uint8Array(readFileSync(join(here, name))));
    chunks.push(new Uint8Array([0x00]));
  }
  let total = 0;
  for (const c of chunks) total += c.length;
  const concatenated = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    concatenated.set(c, offset);
    offset += c.length;
  }
  return sha256(concatenated);
}

// F-CRYPTO-1 (security-audit-2026-06-02): wire the previously-dangling
// bootstrap guard. `assertNoBinaryHashOverridesInProduction` had ZERO callers
// (per the finding grep), so the production fail-fast it documents never
// fired. The combiner's binary-integrity module is on the σ hot path and is
// imported transitively by every reveal-pipeline entry, so calling it at
// module load is the earliest fail-fast point reachable in-process: a
// production process that ships with `CEALIS_COMBINER_BINARY_HASH` /
// `..._SEED` set now throws at import time rather than silently allowing the
// test-only override into the live attestation path. The guard is a no-op
// outside `NODE_ENV=production`, so test runs (which legitimately use the
// override env in `combiner-stale-plugin-hash.test.ts`) are unaffected.
assertNoBinaryHashOverridesInProduction(process.env);
