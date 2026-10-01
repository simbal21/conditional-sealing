import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import type { CircuitName } from "../circuits/index.js";
import type { PublicInputRecord } from "./public-input-ordering.js";

const FIELD_TAG = 10616565558337024268832812441807306647702700357471186337220733986053547943625n;
const MERKLE_TAG = 20140787375993896470384773877394070856137159747959843757523163060061810412835n;
const CLAIM_TAG = 11614045815639004896707968084036073694093708135925582797465573164437456239414n;
const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const MERKLE_DEPTH = 16;

export interface CircuitWitnessInput {
  readonly [key: string]: string | readonly string[];
}

export interface CircuitFixture {
  readonly circuit: CircuitName;
  readonly input: CircuitWitnessInput;
  readonly publicInputs: PublicInputRecord;
}

type PoseidonFn = (values: readonly bigint[]) => bigint;

interface PoseidonModule {
  readonly buildPoseidon: () => Promise<((values: readonly bigint[]) => Uint8Array) & { readonly F: { toObject(v: Uint8Array): bigint } }>;
}

async function loadPoseidon(): Promise<PoseidonFn> {
  const mod = (await import("circomlibjs")) as PoseidonModule;
  const poseidon = await mod.buildPoseidon();
  return (values: readonly bigint[]) => poseidon.F.toObject(poseidon(values));
}

function modInv(a: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = BN254_PRIME;
  let newR = ((a % BN254_PRIME) + BN254_PRIME) % BN254_PRIME;
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r > 1n) throw new Error("value has no inverse");
  return t < 0n ? t + BN254_PRIME : t;
}

function bits64(value: bigint): readonly string[] {
  return Array.from({ length: 64 }, (_, i) => ((value >> BigInt(i)) & 1n).toString());
}

function rootFromPath(poseidon: PoseidonFn, leaf: bigint, siblings: readonly bigint[], path: readonly bigint[]): bigint {
  let current = leaf;
  for (let i = 0; i < siblings.length; i++) {
    const sibling = siblings[i] ?? 0n;
    const direction = path[i] ?? 0n;
    current = direction === 0n
      ? poseidon([MERKLE_TAG, current, sibling])
      : poseidon([MERKLE_TAG, sibling, current]);
  }
  return current;
}

function strings(values: readonly bigint[]): readonly string[] {
  return values.map((v) => v.toString());
}

function basePublic(predicate0: bigint, predicate1: bigint, predicate2: bigint, root: bigint): PublicInputRecord {
  const fieldId = 901n;
  return {
    authorization_scalar: 101n,
    h_commit_scalar: 102n,
    partner_scalar: 103n,
    pda_scalar: 104n,
    claim_scalar: 105n,
    field_set_digest_scalar: fieldId,
    sdMerkleRoot: root,
    predicate_param_0: predicate0,
    predicate_param_1: predicate1,
    predicate_param_2: predicate2,
    expiry_timestamp: 1_800_000_000n,
    revocation_scalar: 106n,
    verifier_ref_scalar: 107n,
    proof_context_scalar: 108n,
  };
}

export async function makeCircuitFixture(circuit: CircuitName): Promise<CircuitFixture> {
  const poseidon = await loadPoseidon();
  const value = circuit === "range" ? 42n : circuit === "non_equality" ? 77n : 55n;
  const salt = 222n;
  const fieldId = 901n;
  const fieldIndex = 0n;
  const policyCode = 2n;
  const siblings = Array<bigint>(MERKLE_DEPTH).fill(0n);
  const path = Array<bigint>(MERKLE_DEPTH).fill(0n);
  const commitment = poseidon([FIELD_TAG, 101n, fieldId, salt, value]);
  const leaf = poseidon([MERKLE_TAG, fieldIndex, fieldId, commitment, policyCode]);
  const sdRoot = rootFromPath(poseidon, leaf, siblings, path);

  const common: Record<string, string | readonly string[]> = {
    value: value.toString(),
    salt: salt.toString(),
    field_id: fieldId.toString(),
    field_index: fieldIndex.toString(),
    policy_code: policyCode.toString(),
    merkle_siblings: strings(siblings),
    merkle_path_indices: strings(path),
  };

  if (circuit === "equality") {
    const publicInputs = basePublic(value, 0n, 0n, sdRoot);
    return { circuit, publicInputs, input: { ...publicToWitness(publicInputs), ...common } };
  }
  if (circuit === "non_equality") {
    const forbidden = 78n;
    const publicInputs = basePublic(forbidden, 0n, 0n, sdRoot);
    return {
      circuit,
      publicInputs,
      input: { ...publicToWitness(publicInputs), ...common, inv: modInv(value - forbidden).toString() },
    };
  }
  if (circuit === "range") {
    const publicInputs = basePublic(18n, 99n, 64n, sdRoot);
    return {
      circuit,
      publicInputs,
      input: { ...publicToWitness(publicInputs), ...common, value_bits: bits64(value) },
    };
  }

  const setSiblings = Array<bigint>(MERKLE_DEPTH).fill(0n);
  const setPath = Array<bigint>(MERKLE_DEPTH).fill(0n);
  const setLeaf = poseidon([CLAIM_TAG, 0n, value]);
  const setRoot = rootFromPath(poseidon, setLeaf, setSiblings, setPath);
  const publicInputs = basePublic(setRoot, 0n, 0n, sdRoot);
  return {
    circuit,
    publicInputs,
    input: {
      ...publicToWitness(publicInputs),
      ...common,
      set_member_index: "0",
      set_siblings: strings(setSiblings),
      set_path_indices: strings(setPath),
    },
  };
}

function publicToWitness(publicInputs: PublicInputRecord): Record<string, string> {
  return Object.fromEntries(Object.entries(publicInputs).map(([k, v]) => [k, v.toString()]));
}

export function findPackageRoot(startUrl = import.meta.url): string {
  const here = dirname(fileURLToPath(startUrl));
  return resolve(here, "..", "..");
}
