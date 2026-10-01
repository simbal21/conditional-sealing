import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils.js";

export type CircuitName = "equality" | "non_equality" | "range" | "set_membership";

export interface CircuitMetadata {
  readonly name: CircuitName;
  readonly familyIdHex: string;
  readonly circuitVersion: number;
  readonly budgetKey: "equality_d16" | "non_equality_d16" | "range_64_d16" | "merkle_set_d16";
  readonly sourceFile: string;
}

function familyId(label: string): string {
  return bytesToHex(keccak_256(utf8ToBytes(`CEALIS_SD_CIRCUIT_${label.toUpperCase()}_V3`)));
}

export const CIRCUIT_VERSION = 1 as const;

export const CIRCUITS: ReadonlyArray<CircuitMetadata> = Object.freeze([
  {
    name: "equality",
    familyIdHex: familyId("equality"),
    circuitVersion: CIRCUIT_VERSION,
    budgetKey: "equality_d16",
    sourceFile: "circuits/equality.circom",
  },
  {
    name: "non_equality",
    familyIdHex: familyId("non_equality"),
    circuitVersion: CIRCUIT_VERSION,
    budgetKey: "non_equality_d16",
    sourceFile: "circuits/non_equality.circom",
  },
  {
    name: "range",
    familyIdHex: familyId("range"),
    circuitVersion: CIRCUIT_VERSION,
    budgetKey: "range_64_d16",
    sourceFile: "circuits/range.circom",
  },
  {
    name: "set_membership",
    familyIdHex: familyId("set_membership"),
    circuitVersion: CIRCUIT_VERSION,
    budgetKey: "merkle_set_d16",
    sourceFile: "circuits/set_membership.circom",
  },
]);

export function getCircuitMetadata(name: CircuitName): CircuitMetadata {
  const found = CIRCUITS.find((c) => c.name === name);
  if (!found) {
    throw new Error(`Unknown circuit: ${name}`);
  }
  return found;
}
