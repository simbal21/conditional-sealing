import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

import type { CircuitName } from "../circuits/index.js";
import type { CircuitWitnessInput } from "./witness-generation.js";

export type ProofGenerationStatus = "complete" | "partial" | "failed" | "not_configured";

export interface GeneratedProof {
  readonly status: ProofGenerationStatus;
  readonly proof: unknown;
  readonly publicSignals: readonly string[];
  readonly verified: boolean;
}

function packageRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
}

function snarkjsBin(root: string): string {
  return resolve(root, "node_modules", ".bin", "snarkjs");
}

export function generatePlonkProof(circuit: CircuitName, input: CircuitWitnessInput): GeneratedProof {
  const root = packageRoot();
  const work = mkdtempSync(resolve(tmpdir(), `cealis-${circuit}-`));
  const inputPath = resolve(work, "input.json");
  const proofPath = resolve(work, "proof.json");
  const publicPath = resolve(work, "public.json");
  const wasmPath = resolve(root, "build", "circuits", circuit, `${circuit}_js`, `${circuit}.wasm`);
  const zkeyPath = resolve(root, "setup", circuit, "zkey.zkey");
  const vkeyPath = resolve(root, "setup", circuit, "vkey.json");
  mkdirSync(dirname(inputPath), { recursive: true });
  writeFileSync(inputPath, JSON.stringify(input, null, 2));

  const snarkjs = snarkjsBin(root);
  execFileSync(snarkjs, ["plonk", "fullprove", inputPath, wasmPath, zkeyPath, proofPath, publicPath], {
    cwd: root,
    stdio: "pipe",
  });
  execFileSync(snarkjs, ["plonk", "verify", vkeyPath, publicPath, proofPath], { cwd: root, stdio: "pipe" });
  return {
    status: "complete",
    proof: JSON.parse(readFileSync(proofPath, "utf-8")) as unknown,
    publicSignals: JSON.parse(readFileSync(publicPath, "utf-8")) as readonly string[],
    verified: true,
  };
}

/**
 * Standalone PLONK verification — accepts an externally-generated proof +
 * public signals and runs `snarkjs plonk verify` against the circuit's
 * verification key (`setup/<circuit>/vkey.json`).
 *
 * Use this when the partner-SDK Verifier callback receives `(proof, publicInputs)`
 * detached from `generatePlonkProof()`'s internal verify (e.g., when a stub-
 * verifier path is being replaced by a real verify lane in v3-demo's Round 3
 * structural tests under `VITEST_PLONK_REAL=1`). The genesis-time verify in
 * `generatePlonkProof()` cannot satisfy this because the Verifier interface
 * (`v3-sd/sdk/types.ts` §158) calls `verifyProof(proof, publicInputs)` as a
 * standalone predicate.
 *
 * Returns true iff the proof verifies; returns false on any snarkjs failure.
 * Never throws — the callback contract is `boolean | Promise<boolean>`.
 */
export function verifyPlonkProof(
  circuit: CircuitName,
  proof: unknown,
  publicSignals: readonly string[],
): boolean {
  const root = packageRoot();
  const work = mkdtempSync(resolve(tmpdir(), `cealis-${circuit}-verify-`));
  const proofPath = resolve(work, "proof.json");
  const publicPath = resolve(work, "public.json");
  const vkeyPath = resolve(root, "setup", circuit, "vkey.json");
  mkdirSync(dirname(proofPath), { recursive: true });
  writeFileSync(proofPath, JSON.stringify(proof));
  writeFileSync(publicPath, JSON.stringify(publicSignals));

  const snarkjs = snarkjsBin(root);
  try {
    execFileSync(snarkjs, ["plonk", "verify", vkeyPath, publicPath, proofPath], {
      cwd: root,
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}
