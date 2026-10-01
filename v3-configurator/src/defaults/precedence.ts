import { getArchetypeDefaults } from "./archetype-index.js";
import {
  getUseCaseDefaults,
  type DefaultRecord,
  type DefaultValue,
} from "./use-case-index.js";

export interface DefaultPrecedenceInput {
  readonly use_case?: string;
  readonly archetype?: string;
  readonly use_case_defaults?: DefaultRecord;
  readonly archetype_defaults?: DefaultRecord;
  readonly partner_overrides?: DefaultRecord;
}

export interface AppliedDefaultRecord {
  readonly field_path: string;
  readonly default_value: DefaultValue;
  readonly applied_value: DefaultValue;
  readonly overridden: boolean;
  readonly default_index_used: "use-case" | "archetype" | "neither";
  readonly superseded_archetype_fallback?: DefaultValue;
}

export interface DefaultPrecedenceResult {
  readonly values: DefaultRecord;
  readonly inspection_records: readonly AppliedDefaultRecord[];
}

export function applyDefaultPrecedence(
  input: DefaultPrecedenceInput,
): DefaultPrecedenceResult {
  const archetypeDefaults =
    input.archetype_defaults ?? getArchetypeDefaults(input.archetype);
  const useCaseDefaults =
    input.use_case_defaults ?? getUseCaseDefaults(input.use_case);
  const overrides = input.partner_overrides ?? {};
  const fieldNames = new Set([
    ...Object.keys(archetypeDefaults),
    ...Object.keys(useCaseDefaults),
    ...Object.keys(overrides),
  ]);

  const values: Record<string, DefaultValue> = {};
  const inspection_records: AppliedDefaultRecord[] = [];
  for (const field of [...fieldNames].sort()) {
    const hasUseCase = Object.hasOwn(useCaseDefaults, field);
    const hasArchetype = Object.hasOwn(archetypeDefaults, field);
    const hasOverride = Object.hasOwn(overrides, field);
    const fallback = archetypeDefaults[field];
    const defaultValue = hasUseCase ? useCaseDefaults[field] : fallback;
    const defaultIndex = hasUseCase
      ? "use-case"
      : hasArchetype
        ? "archetype"
        : "neither";
    const appliedValue = hasOverride ? overrides[field] : defaultValue;
    if (appliedValue === undefined) continue;
    values[field] = appliedValue;
    inspection_records.push({
      field_path: field,
      default_value: defaultValue ?? appliedValue,
      applied_value: appliedValue,
      overridden: hasOverride,
      default_index_used: defaultIndex,
      ...(hasUseCase && hasArchetype && fallback !== undefined
        ? { superseded_archetype_fallback: fallback }
        : {}),
    });
  }

  return { values, inspection_records };
}
