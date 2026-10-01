/**
 * M2 contract imports — narrow re-export of ABIs + role hashes consumed
 * by M7 ceremonies. Phase A locks the surface; Phase B/C/D ceremony
 * scripts read JSON artifacts at `contracts/out/<Contract>.sol/<Contract>.json`.
 *
 * NOTE: This file deliberately does NOT eagerly load ABI JSON at import
 * time — Phase A typecheck must stay green even without `forge build`
 * artifacts present. ABIs load lazily in `loadAbi(<contract>)` calls.
 */

import { readFile } from "node:fs/promises";
import { resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

/**
 * Path to the M2 contract `out/` directory relative to the v3-ops package
 * root. Foundry writes ABIs here after `forge build`.
 */
export const M2_OUT_DIR = resolvePath(
  __dirname,
  "..",
  "..",
  "contracts",
  "out",
);

/**
 * Contract names consumed by M7 ceremonies. NOT exhaustive — each ceremony
 * imports the subset it actually needs.
 */
export const M2_CONTRACT_NAMES = Object.freeze([
  "G4AuthorityRegistry",
  "PluginHashRegistry",
  "DSLVersionRegistry",
  "OracleRegistry",
  "OracleSchemaRegistry",
  "QTSPRegistry",
  "ShredRegistry",
  "ChallengeRegistry",
  "G4RefusalRegistry",
  "SupersededCommitRegistry",
  "PartnerRegistry",
  "CealisTimelockController",
  "CealisSecurityMultisig",
  "EmergencyGovernance",
  "DisclosureRegistry",
  "ConditionEngine",
] as const);

export type M2ContractName = (typeof M2_CONTRACT_NAMES)[number];

interface ForgeArtifact {
  readonly abi: ReadonlyArray<unknown>;
  readonly bytecode?: { object?: string };
}

/**
 * Lazy ABI loader. Returns the `abi` array from
 * `<M2_OUT_DIR>/<name>.sol/<name>.json`. Throws if the artifact is
 * missing.
 */
export async function loadAbi(
  name: M2ContractName,
): Promise<ReadonlyArray<unknown>> {
  const path = resolvePath(M2_OUT_DIR, `${name}.sol`, `${name}.json`);
  const raw = await readFile(path, { encoding: "utf-8" });
  const parsed = JSON.parse(raw) as ForgeArtifact;
  return parsed.abi;
}
