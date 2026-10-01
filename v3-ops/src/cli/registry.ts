/**
 * CLI command registry. 19 commands total — App. A/App. B has 17 logical
 * rows; the CLI splits QTSP (row 6 → 2 cmds), Pause (row 12 → 2 cmds),
 * and adds `phase-1-to-phase-2-g4-cutover` (separate from row 2 G4
 * authority rotation per brief deliverables).
 *
 * Foundation test `cli-command-registry.test.ts` asserts:
 *   - command count === 19
 *   - every slug maps to an existing-or-future module in `src/ceremony/`
 *   - --help output mentions all 19 commands
 */
export interface CliCommand {
  readonly slug: string;
  readonly catalogRowNumber: number;
  readonly specSection: string;
  readonly summary: string;
  readonly status: "phase-a-skeleton" | "phase-b" | "phase-c" | "phase-d" | "phase-e";
}

export const CLI_COMMANDS: readonly CliCommand[] = Object.freeze([
  {
    slug: "g4-binary-hash-update",
    catalogRowNumber: 1,
    specSection: "§3",
    summary: "Update G4 Phase 1 binary hash in G4AuthorityRegistry.",
    status: "phase-b",
  },
  {
    slug: "g4-authority-rotation",
    catalogRowNumber: 2,
    specSection: "§4",
    summary: "Rotate G4 authority key (Phase 1 or Phase 2).",
    status: "phase-b",
  },
  {
    slug: "plugin-version-update",
    catalogRowNumber: 3,
    specSection: "§5",
    summary: "Update plugin version + signed distribution manifest.",
    status: "phase-b",
  },
  {
    slug: "oracle-onboarding",
    catalogRowNumber: 4,
    specSection: "§6",
    summary: "Onboard a new oracle (OracleRegistry + OracleSchemaRegistry).",
    status: "phase-b",
  },
  {
    slug: "oracle-rotation",
    catalogRowNumber: 5,
    specSection: "§7",
    summary: "Rotate oracle signing key / schema with tombstone.",
    status: "phase-b",
  },
  {
    slug: "qtsp-onboarding",
    catalogRowNumber: 6,
    specSection: "§7A",
    summary: "Onboard a new QTSP provider (QTSPRegistry).",
    status: "phase-b",
  },
  {
    slug: "qtsp-root-rotation",
    catalogRowNumber: 6,
    specSection: "§7A",
    summary: "Rotate QTSP signing root.",
    status: "phase-b",
  },
  {
    slug: "re-key-stanza-addition",
    catalogRowNumber: 7,
    specSection: "§8",
    summary: "Re-key ceremony: add new stanza generation under fresher primitives.",
    status: "phase-c",
  },
  {
    slug: "dsl-version-update",
    catalogRowNumber: 8,
    specSection: "§9",
    summary: "Add new DSL interpreter version to DSLVersionRegistry.",
    status: "phase-b",
  },
  {
    slug: "wasm-predicate-whitelist-update",
    catalogRowNumber: 10,
    specSection: "§10",
    summary: "Add a new audited WASM predicate to the whitelist.",
    status: "phase-b",
  },
  {
    slug: "pda-plus-governance-update",
    catalogRowNumber: 9,
    specSection: "§10A",
    summary: "PDA+ governance update — sub-classes 1..5 via --sub-class flag.",
    status: "phase-c",
  },
  {
    slug: "shred-trigger",
    catalogRowNumber: 11,
    specSection: "§11",
    summary: "Trigger shred — authority modes Subject/Joint/Operator/Timelock/Disabled.",
    status: "phase-d",
  },
  {
    slug: "pause-activation",
    catalogRowNumber: 12,
    specSection: "§12",
    summary: "Activate bounded pause (Partner/Joint authority, ≤90 days).",
    status: "phase-d",
  },
  {
    slug: "pause-deactivation",
    catalogRowNumber: 12,
    specSection: "§12",
    summary: "Deactivate active pause.",
    status: "phase-d",
  },
  {
    slug: "challenge-registry-resolution",
    catalogRowNumber: 13,
    specSection: "§12.7",
    summary: "Resolve open challenge: confirmNoIntervention / haltCeremony / extendChallenge.",
    status: "phase-d",
  },
  {
    slug: "phase-1-to-phase-2-g4-cutover",
    catalogRowNumber: 2,
    specSection: "§15",
    summary: "Phase 1 → Phase 2 G4 cutover runbook + dry-run (testnet-only at M7).",
    status: "phase-c",
  },
  {
    slug: "disaster-recovery-bundle",
    catalogRowNumber: 15,
    specSection: "§14",
    summary: "Disaster-recovery bundle (testnet-only at M7).",
    status: "phase-d",
  },
  {
    slug: "vault-operator-transition",
    catalogRowNumber: 16,
    specSection: "§14.3",
    summary: "Vault operator transition (7-day planned + emergency read-halt path).",
    status: "phase-d",
  },
  {
    slug: "governance-phase2-transition",
    catalogRowNumber: 17,
    specSection: "§16.5",
    summary: "Governance Phase 2 transition — seat external advisors.",
    status: "phase-c",
  },
]);

export function findCommand(slug: string): CliCommand | undefined {
  return CLI_COMMANDS.find((c) => c.slug === slug);
}

export const CLI_COMMAND_COUNT = 19;
