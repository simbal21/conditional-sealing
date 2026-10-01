// M2 (Cealis V3 contracts) facade for @cealis/v3-configurator.
//
// Purpose: re-expose the M2 Foundry ABI surface needed by the configurator
// for §8.6 triple-root comparison (locally computed pda_root === contract
// helper computePdaRoot === emitted PDARegistered.pdaRoot — mismatch is
// terminal), §10 evolution diff (PDARegistered events drive lineage view),
// and §7.3 partner-readable inspection (on_chain_tx_refs).
//
// IMPORTANT: M2 ships Solidity contracts + Foundry artifact JSON. There is
// NO TypeScript struct export from M2 — the type `PdaRootFields` in
// `contracts/src/lib/Structs.sol` is Solidity-only. The
// configurator consumes M2 via:
//   1. ABI JSON loaded at runtime from `contracts/out/` via
//      viem (this facade exposes ABI accessors, not parsed structs).
//   2. Field-name + field-type contract mirrored verbatim in
//      `src/types/pda-root.ts` — derived from S2-1 §3.3 (29 fields) AND
//      cross-checked against `Structs.sol` PdaRootFields verbatim.
//
// The smoke test `tests/foundation/m2-abi-smoke.test.ts` loads the
// ConditionEngine + (where exposed) registerPDA / computePdaRoot / PDARegistered
// surfaces from the Foundry artifact and asserts the 29-field count matches
// the TypeScript interface. If M2 ever ships 28 fields or renames a field,
// the smoke test halts Phase A before any Codex chunk fires.
//
// NOTE on `registerPDA` / `computePdaRoot` / `PDARegistered`:
//   At time of M4 Phase A authoring (2026-05-11), M2 ships these surfaces
//   inside the ConditionEngine contract surface and Helpers contracts (see
//   contracts/src/helpers/CealisIdentifierHelpers.sol +
//   contracts/src/engine/ConditionEngine.sol). The Foundry artifact path
//   for the ABI is `contracts/out/ConditionEngine.sol/ConditionEngine.json`.
//   The configurator does NOT bind to a fixed contract address at Phase A;
//   Phase E (`src/pda/triple-root-guard.ts`) wires the viem `getContract`
//   call with the deployed-address provided via configurator config.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Load a Foundry artifact JSON for an M2 contract.
 *
 * @param contractName Solidity contract base name (e.g. "ConditionEngine").
 * @returns The parsed Foundry artifact JSON. Caller is responsible for
 *          extracting the `abi` array and locating function/event entries.
 *
 * Throws if the artifact cannot be located (i.e., `forge build` not run).
 * The foundation test catches that case and tells the human to run
 * `forge build` from `contracts/` before retrying Phase A.
 */
export function loadM2Artifact(contractName: string): {
  abi: ReadonlyArray<unknown>;
  bytecode?: { object: string };
  deployedBytecode?: { object: string };
} {
  // Phase A locates artifacts relative to the package root. Adjust as
  // needed when Phase E wires viem ABI loading; for the smoke test we
  // only need the `abi` array.
  const artifactsDir = join(__dirname, "..", "..", "contracts", "out");
  const path = join(artifactsDir, `${contractName}.sol`, `${contractName}.json`);
  const raw = readFileSync(path, "utf8");
  return JSON.parse(raw) as {
    abi: ReadonlyArray<unknown>;
    bytecode?: { object: string };
    deployedBytecode?: { object: string };
  };
}

/**
 * Canonical 29 PdaRootFields names in S2-1 §3.3 / S2-2 App. A order.
 *
 * Cross-checked verbatim against `contracts/src/lib/Structs.sol`
 * `struct PdaRootFields` (29 fields per §3.3.3 16 original + §3.3.4 13 D1
 * additions). The TypeScript-side mirror in `src/types/pda-root.ts` uses
 * snake_case TS names; Solidity-side uses lowerCamelCase. The order MUST
 * match.
 *
 * The foundation test `m1-m2-differential.test.ts` asserts that the
 * TypeScript interface `PdaRootFields` declares exactly these 29 field
 * names (in snake_case) in the same order, and that M1's `PDARootInput`
 * keys cover the same 29 fields.
 */
export const PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE: readonly string[] = [
  // §3.3.3 — original 16 fields
  "pdaId",
  "pdaVersion",
  "revealConditionMode",
  "revealConditionSpecHash",
  "shredConditionMode",
  "shredConditionSpecHash",
  "oracleReferencesRoot",
  "dslVersion",
  "wasmPredicateHashesRoot",
  "submitterSetsRoot",
  "pauseAuthorityId",
  "ceremonyResolverId",
  "eligibleChallengersRevealRoot",
  "eligibleChallengersShredRoot",
  "templateId",
  "partnerId",
  // §3.3.4 — 13 D1 additions
  "subjectAuthenticatorClass",
  "qtspProviderRef",
  "art9Scoped",
  "art9BasisId",
  "legalEffectExpected",
  "cealisClassWideHaltOptOut",
  "minimumShredLatency",
  "applicableJurisdiction",
  "conditionalRecipientsUpdatable",
  "subjectLivenessRequiredAtFire",
  "emergencyResponseBrickingAcknowledgment",
  "timeCriticalPdaFlag",
  "pdaUpdatable",
] as const;

export const PDA_ROOT_FIELDS_COUNT = 29 as const;
