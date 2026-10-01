// S2-4 §4.4 — Stage 3 registry liveness check.

import type { DualFormValidationFailure } from "../../errors/index.js";
import type { ClassTableRow } from "../../types/class-table.js";
import {
  createStage3Failure,
  stage3ValueClass,
  type Stage3PolicyMap,
} from "./allow-list-checker.js";

export interface RegistryReference {
  readonly id: string;
}

export interface RegistryLivenessEntry {
  readonly id: string;
  readonly effectiveBlock: number | bigint;
  readonly tombstonedAtBlock?: number | bigint | null;
}

export type RegistryEntries = Stage3PolicyMap<RegistryLivenessEntry>;

export interface RegistryLivenessCheckInput {
  readonly row: ClassTableRow;
  readonly registryRef: string | RegistryReference | undefined;
  readonly registryEntries: RegistryEntries | undefined;
  readonly intendedCommitBlock: number | bigint;
  readonly sourceFieldPath?: string;
}

export function checkRegistryLiveness(input: RegistryLivenessCheckInput): DualFormValidationFailure | null {
  const registryId = registryReferenceId(input.registryRef);
  if (registryId === null) return null;

  const entry = readRegistryEntry(input.registryEntries, registryId);
  if (entry === undefined) {
    return createStage3Failure({
      row: input.row,
      code: "REGISTRY_REFERENCE_MISSING",
      failedPredicate: "registry reference is absent from the effective PDA+ registry",
      sanitizedValueClass: stage3ValueClass(registryId),
      sourceFieldPath: input.sourceFieldPath,
      partnerAction: "request_pda_plus_change",
      remediationText: "Add the referenced item to the PDA+ registry, or choose an active reference.",
    });
  }

  if (compareBlock(entry.effectiveBlock, input.intendedCommitBlock) > 0) {
    return createStage3Failure({
      row: input.row,
      code: "REGISTRY_REFERENCE_NOT_YET_EFFECTIVE",
      failedPredicate: "registry reference is not effective at the intended commit block",
      sanitizedValueClass: stage3ValueClass(registryId),
      sourceFieldPath: input.sourceFieldPath,
      partnerAction: "choose_different_allowed_option",
      remediationText: "Choose a registry reference that is already effective at the intended commit block.",
    });
  }

  if (
    entry.tombstonedAtBlock !== undefined &&
    entry.tombstonedAtBlock !== null &&
    compareBlock(entry.tombstonedAtBlock, input.intendedCommitBlock) <= 0
  ) {
    return createStage3Failure({
      row: input.row,
      code: "REGISTRY_REFERENCE_TOMBSTONED",
      failedPredicate: "registry reference is tombstoned at the intended commit block",
      sanitizedValueClass: stage3ValueClass(registryId),
      sourceFieldPath: input.sourceFieldPath,
      partnerAction: "choose_different_allowed_option",
      remediationText: "Choose a registry reference that is active at the intended commit block.",
    });
  }

  return null;
}

function registryReferenceId(reference: string | RegistryReference | undefined): string | null {
  if (reference === undefined) return null;
  if (typeof reference === "string") return reference;
  return reference.id;
}

function readRegistryEntry(
  source: RegistryEntries | undefined,
  registryId: string,
): RegistryLivenessEntry | undefined {
  if (source === undefined) return undefined;
  if (isRegistryEntriesReadonlyMap(source)) return source.get(registryId);
  return source[registryId];
}

function isRegistryEntriesReadonlyMap(source: RegistryEntries): source is ReadonlyMap<string, RegistryLivenessEntry> {
  return typeof (source as ReadonlyMap<string, RegistryLivenessEntry>).get === "function";
}

function compareBlock(left: number | bigint, right: number | bigint): number {
  if (typeof left === "bigint" && typeof right === "bigint") {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
  }
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  if (leftNumber < rightNumber) return -1;
  if (leftNumber > rightNumber) return 1;
  return 0;
}
