import {
  evaluateRegistryDeprecationOverlay,
  type RegistryDeprecation,
} from "../simulation/index.js";

export type EvolutionChangeKind = "allowed" | "forbidden" | "registry_overlay";

export interface PdaDiffChange {
  readonly path: string;
  readonly before: unknown;
  readonly after: unknown;
  readonly kind: EvolutionChangeKind;
  readonly reason: string;
}

export interface PdaDiffOptions {
  readonly commitBlock?: bigint | number;
  readonly authorizationBlock?: bigint | number;
  readonly registryReferences?: readonly { readonly registry: string; readonly entry_id: string }[];
  readonly deprecations?: readonly RegistryDeprecation[];
  readonly supersession?: boolean;
}

export interface PdaDiffResult {
  readonly ok: boolean;
  readonly changes: readonly PdaDiffChange[];
  readonly registryOverlay: {
    readonly checked_at_block: bigint;
    readonly halted: boolean;
    readonly affected_entries: readonly string[];
  };
}

const FROZEN_PATHS = new Set([
  "pda_id",
  "partner_id",
  "pda_root_fields",
  "commit_aad_fields",
  "fixed_gates",
  "commit_version",
  "template_id",
]);

const CONDITIONALLY_ALLOWED_PATHS = new Set([
  "pda_version",
  "reveal_challenge_window_seconds",
  "shred_challenge_window_seconds",
  "retention_seconds",
  "minimum_shred_latency_seconds",
  "conditional_recipients",
  "recipients",
  "extension_metadata",
]);

export function diffPdaEvolution(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  options: PdaDiffOptions = {},
): PdaDiffResult {
  const pdaUpdatable =
    after.pda_updatable === true ||
    before.pda_updatable === true ||
    recordValue(after.extension_metadata).pda_updatable === true ||
    recordValue(before.extension_metadata).pda_updatable === true;
  const conditionalUpdatable =
    after.conditional_recipients_updatable === true ||
    before.conditional_recipients_updatable === true ||
    recordValue(after.extension_metadata).conditional_recipients_updatable === true ||
    recordValue(before.extension_metadata).conditional_recipients_updatable === true;
  const changes = diffRecords(before, after).map((change) =>
    classifyChange(change, { pdaUpdatable, conditionalUpdatable, supersession: options.supersession === true }),
  );
  const overlay = evaluateRegistryDeprecationOverlay({
    pda_root_commit_block: options.commitBlock ?? 0n,
    authorization_block: options.authorizationBlock ?? options.commitBlock ?? 0n,
    referenced_entries: options.registryReferences ?? [],
    deprecations: options.deprecations ?? [],
  });
  const overlayChanges: PdaDiffChange[] = overlay.affected_entries.map((entry) => ({
    path: `registry:${entry}`,
    before: "active_at_commit",
    after: "deprecated_at_authorization",
    kind: "registry_overlay",
    reason: "Registry deprecation overlay is evaluated at authorization block.",
  }));
  const allChanges = [...changes, ...overlayChanges];
  return {
    ok: allChanges.every((change) => change.kind !== "forbidden") && !overlay.halted,
    changes: allChanges,
    registryOverlay: overlay,
  };
}

function classifyChange(
  change: Omit<PdaDiffChange, "kind" | "reason">,
  context: {
    readonly pdaUpdatable: boolean;
    readonly conditionalUpdatable: boolean;
    readonly supersession: boolean;
  },
): PdaDiffChange {
  if (FROZEN_PATHS.has(change.path) && !context.supersession) {
    return {
      ...change,
      kind: "forbidden",
      reason: "Frozen commit-bound field requires explicit supersession ceremony.",
    };
  }
  if (change.path === "conditional_recipients" && !context.conditionalUpdatable) {
    return {
      ...change,
      kind: "forbidden",
      reason: "Conditional-recipient changes require the updatable flag or supersession.",
    };
  }
  if (CONDITIONALLY_ALLOWED_PATHS.has(change.path) && context.pdaUpdatable) {
    return {
      ...change,
      kind: "allowed",
      reason: "Two-layer evolution allows this update on a PDA-updatable surface.",
    };
  }
  if (context.supersession) {
    return {
      ...change,
      kind: "allowed",
      reason: "Explicit supersession ceremony emits a new PDA root without reinterpreting old commits.",
    };
  }
  return {
    ...change,
    kind: "forbidden",
    reason: "Update path is not allowed without pda_updatable or supersession.",
  };
}

function diffRecords(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): readonly Omit<PdaDiffChange, "kind" | "reason">[] {
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  return keys
    .filter((key) => stableString(before[key]) !== stableString(after[key]))
    .map((key) => ({ path: key, before: before[key], after: after[key] }));
}

function stableString(value: unknown): string {
  return JSON.stringify(normalize(value));
}

function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function normalize(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array) return Array.from(value);
  if (Array.isArray(value)) return value.map((entry) => normalize(entry));
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = normalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}
