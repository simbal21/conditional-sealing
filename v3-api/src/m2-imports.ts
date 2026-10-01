// M2 (Foundry contracts) ABI facade for @cealis/v3-api.
//
// Purpose: centralize Foundry artifact loading so Codex chunks (B chain-anchor,
// C event-listener, D vault) don't re-parse the ABI JSON or guess event signatures.
//
// Drift guard: if M2 redeploys with a different RevealAuthorized signature, the
// foundation test `tests/foundation/m2-abi-smoke.test.ts` halts before any
// Codex chunk fires.
//
// Per PHASE-PLAN A3 — the three contracts M5 reads:
//   - ConditionEngine: RevealAuthorized event (event-driven reveal flow)
//   - IShredRegistryD2: currentShredState lookup (read-only at reveal)
//   - IG4RefusalRegistryD2: G4 refusal entries (read-only for refusal status)
//
// Foundry artifacts are loaded at boot via `loadConditionEngineAbi()` etc. so
// the facade itself stays light (no top-level fs reads — keeps Phase A clean).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// Artifact paths (relative to the workspace root contracts/out).
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CONTRACTS_OUT_DIR = resolve(__dirname, "../../contracts/out");

export const ARTIFACT_PATHS = {
  ConditionEngine: resolve(CONTRACTS_OUT_DIR, "ConditionEngine.sol/ConditionEngine.json"),
  IShredRegistryD2: resolve(CONTRACTS_OUT_DIR, "ConditionEngine.sol/IShredRegistryD2.json"),
  IG4RefusalRegistryD2: resolve(CONTRACTS_OUT_DIR, "ConditionEngine.sol/IG4RefusalRegistryD2.json"),
} as const;

export type AbiInput = {
  name: string;
  type: string;
  indexed?: boolean;
  internalType?: string;
  components?: AbiInput[];
};

export type AbiEvent = {
  type: "event";
  name: string;
  inputs: AbiInput[];
  anonymous?: boolean;
};

export type AbiFunction = {
  type: "function";
  name: string;
  inputs: AbiInput[];
  outputs?: AbiInput[];
  stateMutability?: string;
};

export type AbiItem = AbiEvent | AbiFunction | { type: string; [k: string]: unknown };

export type ContractArtifact = {
  abi: AbiItem[];
  bytecode?: { object: string };
  deployedBytecode?: { object: string };
};

/**
 * Load a Foundry artifact JSON from disk. Per PHASE-PLAN A3, M5 reads three:
 * ConditionEngine + IShredRegistryD2 + IG4RefusalRegistryD2. Phase B/C/D import
 * via this facade — never via direct `readFileSync` in route code.
 */
export function loadArtifact(name: keyof typeof ARTIFACT_PATHS): ContractArtifact {
  const path = ARTIFACT_PATHS[name];
  const text = readFileSync(path, "utf-8");
  return JSON.parse(text) as ContractArtifact;
}

/**
 * Locate the `RevealAuthorized` event in the ConditionEngine ABI. Used by
 * Phase C event-listener for `viem` log decoding + Phase D verify route for
 * cross-check against bundle `chain_proofs`.
 *
 * Per S2-2 §12 + M2 artifact: 7 inputs total (3 indexed topics + 4 data fields).
 *   - authorizationId (indexed) - bytes32
 *   - hCommit (indexed)         - bytes32
 *   - pdaRoot (indexed)         - bytes32
 *   - authorizationBlock        - uint64
 *   - authorizationTimestamp    - uint64
 *   - challengeWindow           - uint32
 *   - conditionRef              - bytes32
 *
 * NOTE for SPEC-COMPLIANCE-GUARD §0 item: PHASE-PLAN A3 says "7 topics" but
 * the correct count is "7 inputs" (4 topics total: 1 signature + 3 indexed).
 * This facade reads the source artifact verbatim — no wording drift here.
 */
export function getRevealAuthorizedEvent(artifact: ContractArtifact): AbiEvent {
  const ev = artifact.abi.find(
    (item): item is AbiEvent => item.type === "event" && (item as AbiEvent).name === "RevealAuthorized",
  );
  if (!ev) {
    throw new Error("M2 ABI drift: ConditionEngine.RevealAuthorized event not found in artifact.");
  }
  return ev;
}

/**
 * Convenience: ABI-only export for `viem` callers.
 */
export function getConditionEngineAbi(): AbiItem[] {
  return loadArtifact("ConditionEngine").abi;
}

export function getShredRegistryAbi(): AbiItem[] {
  return loadArtifact("IShredRegistryD2").abi;
}

export function getG4RefusalRegistryAbi(): AbiItem[] {
  return loadArtifact("IG4RefusalRegistryD2").abi;
}

/**
 * Expected RevealAuthorized input names + types — locked at Phase A from
 * `contracts/out/ConditionEngine.sol/ConditionEngine.json`.
 * Foundation test asserts the artifact matches this expectation.
 */
export const REVEAL_AUTHORIZED_EXPECTED_INPUTS: ReadonlyArray<{
  name: string;
  type: string;
  indexed: boolean;
}> = [
  { name: "authorizationId", type: "bytes32", indexed: true },
  { name: "hCommit", type: "bytes32", indexed: true },
  { name: "pdaRoot", type: "bytes32", indexed: true },
  { name: "authorizationBlock", type: "uint64", indexed: false },
  { name: "authorizationTimestamp", type: "uint64", indexed: false },
  { name: "challengeWindow", type: "uint32", indexed: false },
  { name: "conditionRef", type: "bytes32", indexed: false },
] as const;
