// S2-4 §4.4 / §13.5 — Stage 3 content-addressed template id active check.

import type { DualFormValidationFailure } from "../../errors/index.js";
import type { ClassTableRow } from "../../types/class-table.js";
import { createStage3Failure, stage3ValueClass } from "./allow-list-checker.js";

export type ActiveTemplateIds = ReadonlySet<string> | readonly string[];

export interface TemplateIdActiveCheckInput {
  readonly row: ClassTableRow;
  readonly templateId: string | undefined;
  readonly activeTemplateIds: ActiveTemplateIds | undefined;
  readonly sourceFieldPath?: string;
}

export function checkTemplateIdActive(input: TemplateIdActiveCheckInput): DualFormValidationFailure | null {
  if (input.templateId === undefined) return null;

  if (!isContentAddressedTemplateId(input.templateId)) {
    return createStage3Failure({
      row: input.row,
      code: "TEMPLATE_ID_NOT_CONTENT_ADDRESSED",
      failedPredicate: "template id is not content-addressed",
      sanitizedValueClass: stage3ValueClass(input.templateId),
      sourceFieldPath: input.sourceFieldPath,
      partnerAction: "choose_different_allowed_option",
      remediationText: "Use an active content-addressed template id.",
    });
  }

  if (!hasActiveTemplate(input.activeTemplateIds, input.templateId)) {
    return createStage3Failure({
      row: input.row,
      code: "TEMPLATE_ID_INACTIVE",
      failedPredicate: "template id is content-addressed but not active",
      sanitizedValueClass: stage3ValueClass(input.templateId),
      sourceFieldPath: input.sourceFieldPath,
      partnerAction: "choose_different_allowed_option",
      remediationText: "Choose a content-addressed template id that is active in PDA+.",
    });
  }

  return null;
}

function isContentAddressedTemplateId(templateId: string): boolean {
  return /^sha256:[a-f0-9]{64}$/i.test(templateId) || /^0x[a-f0-9]{64}$/i.test(templateId);
}

function hasActiveTemplate(activeTemplateIds: ActiveTemplateIds | undefined, templateId: string): boolean {
  if (activeTemplateIds === undefined) return false;
  // Content-addressed ids are hex; normalize case so a registered lowercase id
  // matches an uppercased submission and vice versa.
  const needle = templateId.toLowerCase();
  if (isReadonlyStringSet(activeTemplateIds)) {
    if (activeTemplateIds.has(templateId) || activeTemplateIds.has(needle)) return true;
    for (const id of activeTemplateIds) {
      if (id.toLowerCase() === needle) return true;
    }
    return false;
  }
  return activeTemplateIds.some((id) => id.toLowerCase() === needle);
}

function isReadonlyStringSet(activeTemplateIds: ActiveTemplateIds): activeTemplateIds is ReadonlySet<string> {
  return typeof (activeTemplateIds as ReadonlySet<string>).has === "function";
}
