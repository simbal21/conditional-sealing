// @cealis/v3-demo/m2-imports — typed re-export facade for M2 contract ABIs.
//
// NO RE-AUTHORING. ABIs are loaded from the Foundry-compiled JSON artifacts
// under `contracts/out/<Contract>.sol/<Contract>.json`. This is
// the M2 lesson: never paraphrase an ABI by hand — read the bytes that the
// Solidity compiler produced.
//
// Addresses are resolved at runtime from environment variables populated by
// `setup.ts` (env vars per contract, e.g. `CONDITION_ENGINE_ADDRESS`). At
// Phase A we only declare the ENV var name registry + a typed loader; round
// implementations consume these via `setup.ts.getContractAddress(name)`.
//
// Per Rule 36 / Codex sandbox network restriction: ABIs are loaded
// synchronously at module init using `readFileSync` against repo-relative
// paths. No network fetch, no install-time codegen.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Resolve the contracts/out directory relative to THIS module.
// Layout: v3-demo/src/m2-imports.ts → ../../contracts/out
const HERE = dirname(fileURLToPath(import.meta.url));
const CONTRACTS_OUT = resolve(HERE, "..", "..", "contracts", "out");

export const M2_CONTRACT_NAMES = [
  "ConditionEngine",
  "ShredRegistry",
  "ChallengeRegistry",
  "DisclosureRegistry",
  "DisclosureRevocationRegistry",
  "PluginHashRegistry",
  "G4AuthorityRegistry",
  "DSLVersionRegistry",
  "OracleRegistry",
  "QTSPRegistry",
] as const;

export type M2ContractName = (typeof M2_CONTRACT_NAMES)[number];

/**
 * Maps contract name → env-var name that must be set with its on-chain
 * address. Populated by Phase G live deploy + Anvil-fork CI bootstrap.
 */
export const M2_ADDRESS_ENV_VAR: Readonly<Record<M2ContractName, string>> = {
  ConditionEngine: "CONDITION_ENGINE_ADDRESS",
  ShredRegistry: "SHRED_REGISTRY_ADDRESS",
  ChallengeRegistry: "CHALLENGE_REGISTRY_ADDRESS",
  DisclosureRegistry: "DISCLOSURE_REGISTRY_ADDRESS",
  DisclosureRevocationRegistry: "DISCLOSURE_REVOCATION_REGISTRY_ADDRESS",
  PluginHashRegistry: "PLUGIN_HASH_REGISTRY_ADDRESS",
  G4AuthorityRegistry: "G4_AUTHORITY_REGISTRY_ADDRESS",
  DSLVersionRegistry: "DSL_VERSION_REGISTRY_ADDRESS",
  OracleRegistry: "ORACLE_REGISTRY_ADDRESS",
  QTSPRegistry: "QTSP_REGISTRY_ADDRESS",
};

/**
 * The shape of a single ABI item (function/event/error). We accept Foundry's
 * full output shape; the loader returns the `abi` array which viem accepts
 * directly as `Abi`.
 */
export type AbiItem = Readonly<Record<string, unknown>>;
export type Abi = readonly AbiItem[];

interface ForgeArtifact {
  readonly abi: Abi;
  readonly bytecode?: { readonly object?: string };
  readonly deployedBytecode?: { readonly object?: string };
}

function loadArtifact(name: M2ContractName): ForgeArtifact {
  const path = resolve(CONTRACTS_OUT, `${name}.sol`, `${name}.json`);
  const raw = readFileSync(path, "utf8");
  return JSON.parse(raw) as ForgeArtifact;
}

/**
 * ABI lookup — call at any time; reads from `contracts/out/`. Throws via
 * the native fs error if the artifact is missing (i.e. `forge build` not run).
 */
export function getAbi(name: M2ContractName): Abi {
  return loadArtifact(name).abi;
}

/**
 * Pre-loaded ABI map. Eagerly resolved at module init so missing artifacts
 * fail fast at boot rather than at first round call.
 */
export const M2_ABIS: Readonly<Record<M2ContractName, Abi>> = (() => {
  const result: Partial<Record<M2ContractName, Abi>> = {};
  for (const name of M2_CONTRACT_NAMES) {
    result[name] = getAbi(name);
  }
  return result as Readonly<Record<M2ContractName, Abi>>;
})();

/**
 * Address resolver — round code calls this with a contract name; we look
 * up the env var and return the address. Throws DemoError at the call site
 * (see setup.ts.getContractAddress) — this helper is the raw env lookup.
 */
export function readAddressFromEnv(name: M2ContractName): `0x${string}` | undefined {
  const envName = M2_ADDRESS_ENV_VAR[name];
  const value = process.env[envName];
  if (value === undefined || value === "") return undefined;
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) return undefined;
  return value as `0x${string}`;
}

/**
 * The Round 2 "absence-of-event" assertion needs the event signature for
 * `RevealAuthorized`. Pre-extracted here so assertion code doesn't grep ABIs
 * inline.
 */
export const M2_EVENT_NAMES = {
  RevealAuthorized: "RevealAuthorized",
  ShredAuthorized: "ShredAuthorized",
  ShredFinalized: "ShredFinalized",
  ChallengeOpened: "ChallengeOpened",
  ChallengeResolved: "ChallengeResolved",
} as const;

export type M2EventName = (typeof M2_EVENT_NAMES)[keyof typeof M2_EVENT_NAMES];
