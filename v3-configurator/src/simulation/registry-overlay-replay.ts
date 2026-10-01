import type {
  RegistryDeprecation,
  RegistryOverlayReplayInput,
  RegistryOverlayReplayResult,
  SimulationSubStepResult,
} from "./types.js";

function toBigInt(value: bigint | number): bigint {
  return typeof value === "bigint" ? value : BigInt(Math.trunc(value));
}

function key(entry: {
  readonly registry: string;
  readonly entry_id: string;
}): string {
  return `${entry.registry}:${entry.entry_id}`;
}

function deprecationApplies(
  deprecation: RegistryDeprecation,
  authorizationBlock: bigint,
): boolean {
  return toBigInt(deprecation.deprecated_at_block) <= authorizationBlock;
}

export function evaluateRegistryDeprecationOverlay(
  input: RegistryOverlayReplayInput,
): RegistryOverlayReplayResult {
  const authorizationBlock = toBigInt(input.authorization_block);
  const referenced = new Set(input.referenced_entries.map(key));
  const affectedEntries = input.deprecations
    .filter(
      (deprecation) =>
        referenced.has(key(deprecation)) &&
        deprecationApplies(deprecation, authorizationBlock),
    )
    .map(key);
  return {
    halted: affectedEntries.length > 0,
    checked_at_block: authorizationBlock,
    affected_entries: affectedEntries,
  };
}

export function runRegistryOverlayReplay(
  input: RegistryOverlayReplayInput,
): SimulationSubStepResult {
  const result = evaluateRegistryDeprecationOverlay(input);
  return {
    step: "registry-overlay",
    ok: !result.halted,
    details: result.halted
      ? `Registry deprecation overlay halts authorization at block ${String(result.checked_at_block)} for ${result.affected_entries.join(",")}.`
      : `Registry deprecation overlay checked authorization block ${String(result.checked_at_block)} with no active deprecation.`,
  };
}
