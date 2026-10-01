// M2 (Foundry contracts) ABI facade for @cealis/v3-sd.
//
// Reads:
//   contracts/out/DisclosureRegistry.sol/DisclosureRegistry.json
//   contracts/out/DisclosureRevocationRegistry.sol/DisclosureRevocationRegistry.json
//
// Per PHASE-PLAN §0 item #2: M2 contracts are already deployed-shape. M6
// reads the ABIs to wire viem clients (Phase D) + SDK revocation client
// (Phase E). The artifacts themselves are NOT modified by M6 except for the
// surgical APPEND-ONLY edit of `DisclosureRegistry.sol` documented in
// PHASE-PLAN §D + SPEC-COMPLIANCE-GUARD-M6 §22.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CONTRACTS_OUT_DIR = resolve(__dirname, "../../contracts/out");

export const M2_ARTIFACT_PATHS = {
  DisclosureRegistry: resolve(CONTRACTS_OUT_DIR, "DisclosureRegistry.sol/DisclosureRegistry.json"),
  DisclosureRevocationRegistry: resolve(
    CONTRACTS_OUT_DIR,
    "DisclosureRevocationRegistry.sol/DisclosureRevocationRegistry.json",
  ),
} as const;

export type M2ArtifactName = keyof typeof M2_ARTIFACT_PATHS;

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

export type AbiError = {
  type: "error";
  name: string;
  inputs: AbiInput[];
};

export type AbiItem = AbiEvent | AbiFunction | AbiError | { type: string; [k: string]: unknown };

export type ContractArtifact = {
  abi: AbiItem[];
  bytecode?: { object: string };
  deployedBytecode?: { object: string };
};

/** Load M2 Foundry artifact JSON from disk. */
export function loadM2Artifact(name: M2ArtifactName): ContractArtifact {
  const path = M2_ARTIFACT_PATHS[name];
  const text = readFileSync(path, "utf-8");
  return JSON.parse(text) as ContractArtifact;
}

/**
 * Expected `DisclosureRegistry` function signatures consumed by Phase D viem
 * clients. Phase A smoke test asserts each function is present in the ABI
 * with the expected input ordering (typed via name match).
 *
 * Per `contracts/src/disclosure/DisclosureRegistry.sol`:
 *   - verifyDisclosureProof(bytes32, bytes32, bytes32, bytes32, bytes, bytes) returns(bool)
 *   - verifyAndCommitDisclosure(bytes32, bytes32, bytes32, bytes32, bytes, bytes, bytes32) returns(bool)
 *   - commitDisclosure(bytes32, bytes32, bytes32)
 *   - registerVerifier(bytes32)
 *   - registerVerifierContract(bytes32, address)
 *   - disclosureRevoked(bytes32) returns(bool)
 *   - revocationRegistry() returns(address)
 *   - disclosureDigest(bytes32) returns(bytes32)
 */
export const EXPECTED_DISCLOSURE_REGISTRY_FUNCTIONS = Object.freeze([
  "verifyDisclosureProof",
  "verifyAndCommitDisclosure",
  "commitDisclosure",
  "registerVerifier",
  "registerVerifierContract",
  "disclosureRevoked",
  "revocationRegistry",
  "disclosureDigest",
] as const);

/**
 * Expected `DisclosureRegistry` event signatures consumed by SDK + viem clients.
 *
 *   DisclosureCommitted(bytes32 indexed disclosureId, bytes32 indexed authorizationId, bytes32 proofDigest)
 *   DisclosureProofVerified(bytes32 indexed disclosureId, bytes32 indexed authorizationId, bytes32 verifierRef)
 *   DisclosureVerifierRegistered(bytes32 indexed verifierRef)
 *
 *   DisclosureVerifierContractRegistered(bytes32 indexed verifierRef, address indexed verifierContract)
 */
export const EXPECTED_DISCLOSURE_REGISTRY_EVENTS = Object.freeze([
  "DisclosureCommitted",
  "DisclosureProofVerified",
  "DisclosureVerifierRegistered",
  "DisclosureVerifierContractRegistered",
] as const);

/**
 * Expected `DisclosureRevocationRegistry` function signatures consumed by
 * Phase D viem clients + Phase E SDK.
 *
 * Per `contracts/src/disclosure/DisclosureRevocationRegistry.sol`:
 *   - registerDisclosure(bytes32, bytes32, bytes32, bytes32, uint64, address)
 *   - revokeDisclosure(bytes32, uint8, bytes32)
 *   - isRevoked(bytes32) returns(bool)
 *   - authorizedRevoker(bytes32) returns(address)
 *   - expiryTimestamp(bytes32) returns(uint64)
 */
export const EXPECTED_REVOCATION_REGISTRY_FUNCTIONS = Object.freeze([
  "registerDisclosure",
  "revokeDisclosure",
  "isRevoked",
  "authorizedRevoker",
  "expiryTimestamp",
] as const);

/**
 * Expected `DisclosureRevocationRegistry` event signatures.
 *
 * §I.11 line 2394 PRIVACY DEFAULT: `DisclosureRevoked` indexes ONLY
 * `disclosureId + authorizationId` — `subject_commitment_v3` is ABSENT.
 *
 *   DisclosureRegistered(bytes32 indexed, bytes32 indexed, bytes32 indexed, bytes32, uint64, address)
 *   DisclosureRevoked(bytes32 indexed, bytes32 indexed, uint8, bytes32)
 */
export const EXPECTED_REVOCATION_REGISTRY_EVENTS = Object.freeze([
  "DisclosureRegistered",
  "DisclosureRevoked",
] as const);

/** Find a function definition in a loaded artifact. Throws on absence. */
export function findFunction(artifact: ContractArtifact, name: string): AbiFunction {
  const fn = artifact.abi.find(
    (i): i is AbiFunction => i.type === "function" && (i as AbiFunction).name === name,
  );
  if (!fn) {
    throw new Error(`M2 ABI drift: function '${name}' not found in artifact.`);
  }
  return fn;
}

/** Find an event definition in a loaded artifact. Throws on absence. */
export function findEvent(artifact: ContractArtifact, name: string): AbiEvent {
  const ev = artifact.abi.find(
    (i): i is AbiEvent => i.type === "event" && (i as AbiEvent).name === name,
  );
  if (!ev) {
    throw new Error(`M2 ABI drift: event '${name}' not found in artifact.`);
  }
  return ev;
}
