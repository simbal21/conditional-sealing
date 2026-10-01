// S2-4 §4.4 — Stage 3 PDA+ allow-list, bounds, registry liveness, and template checks.

import type { DualFormValidationFailure } from "../../errors/index.js";
import type { ClassTableRow, RowId } from "../../types/class-table.js";
import { CLASS_TABLE } from "../class-table/table.js";
import {
  checkAllowList,
  TEMPLATE_PICK_ROW_IDS,
  type AllowListPolicyMap,
  type Stage3Value,
} from "./allow-list-checker.js";
import { checkBounds, type BoundsPolicyMap } from "./bounds-checker.js";
import {
  checkRegistryLiveness,
  type RegistryEntries,
  type RegistryReference,
} from "./registry-liveness-checker.js";
import { checkTemplateIdActive, type ActiveTemplateIds } from "./template-id-active-checker.js";

export interface Stage3SubmittedSurface {
  readonly rowId: RowId;
  readonly value?: Stage3Value;
  readonly sourceFieldPath?: string;
  readonly registryRef?: string | RegistryReference;
  readonly templateId?: string;
}

export interface Stage3ValidationContext {
  readonly classTable?: ReadonlyMap<RowId, ClassTableRow>;
  readonly allowLists?: AllowListPolicyMap;
  readonly bounds?: BoundsPolicyMap;
  readonly registryEntries?: RegistryEntries;
  readonly activeTemplateIds?: ActiveTemplateIds;
  readonly intendedCommitBlock?: number | bigint;
}

export interface Stage3SubmittedPda {
  readonly surfaces: readonly Stage3SubmittedSurface[];
}

export function validateStage3Surface(
  surface: Stage3SubmittedSurface,
  context: Stage3ValidationContext,
): readonly DualFormValidationFailure[] {
  const table = context.classTable ?? CLASS_TABLE;
  const row = table.get(surface.rowId);
  if (row === undefined) {
    throw new Error(`Stage 3 cannot validate unknown class-table row ${surface.rowId}`);
  }

  const failures: DualFormValidationFailure[] = [];
  appendFailure(
    failures,
    checkAllowList({
      row,
      value: surface.value,
      allowLists: context.allowLists,
      sourceFieldPath: surface.sourceFieldPath,
    }),
  );
  appendFailure(
    failures,
    checkBounds({
      row,
      value: surface.value,
      bounds: context.bounds,
      sourceFieldPath: surface.sourceFieldPath,
    }),
  );
  appendFailure(
    failures,
    checkRegistryLiveness({
      row,
      registryRef: surface.registryRef,
      registryEntries: context.registryEntries,
      intendedCommitBlock: context.intendedCommitBlock ?? 0,
      sourceFieldPath: surface.sourceFieldPath,
    }),
  );
  appendFailure(
    failures,
    checkTemplateIdActive({
      row,
      templateId: surface.templateId,
      activeTemplateIds: context.activeTemplateIds,
      sourceFieldPath: surface.sourceFieldPath,
    }),
  );

  return failures;
}

export function validateStage3Pda(
  pda: Stage3SubmittedPda,
  context: Stage3ValidationContext,
): readonly DualFormValidationFailure[] {
  return pda.surfaces.flatMap((surface) => validateStage3Surface(surface, context));
}

function appendFailure(
  failures: DualFormValidationFailure[],
  failure: DualFormValidationFailure | null,
): void {
  if (failure !== null) failures.push(failure);
}

export { TEMPLATE_PICK_ROW_IDS };

export type {
  ActiveTemplateIds,
  AllowListPolicyMap,
  BoundsPolicyMap,
  RegistryEntries,
  RegistryReference,
  Stage3Value,
};

