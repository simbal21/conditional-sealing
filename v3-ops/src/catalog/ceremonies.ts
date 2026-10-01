import { GovernancePath, type CeremonyCatalogRow } from "../types/ceremony.js";

/**
 * 17-row CEREMONY_CATALOG matching S2-6 §2 (16 rows) + §16.5 (Phase 2
 * transition = row 17). Same row count as App. A (17 timeline diagrams)
 * and App. B (17×8 invariant cross-check matrix).
 *
 * Foundation test `ceremony-catalog.test.ts` asserts:
 *   - CEREMONY_CATALOG.length === 17
 *   - row.number values are 1..17 consecutive
 *   - row.slug values are unique
 *   - every entry has at least one governance path
 *
 * NOTE: This catalog is the App. A/App. B logical view. The CLI surface
 * has 19 commands because QTSP (row 6), Pause (row 12), and Phase 1→2 G4
 * cutover expand to multiple invocations. See `src/cli/registry.ts`.
 */
export const CEREMONY_CATALOG: readonly CeremonyCatalogRow[] = Object.freeze([
  {
    number: 1,
    slug: "g4-binary-hash-update",
    name: "G4 binary-hash registry update",
    governance: [
      GovernancePath.TIMELOCK_7D_ADDITION,
      GovernancePath.EXPEDITED_24H_DEPRECATION,
      GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION,
    ],
    surfaces: ["G4AuthorityRegistry", "G4RefusalRegistry"],
    specSection: "§3",
  },
  {
    number: 2,
    slug: "g4-authority-rotation",
    name: "G4 authority key rotation",
    governance: [
      GovernancePath.TIMELOCK_7D_ADDITION,
      GovernancePath.EXPEDITED_24H_DEPRECATION,
    ],
    surfaces: ["G4AuthorityRegistry"],
    specSection: "§4",
  },
  {
    number: 3,
    slug: "plugin-version-update",
    name: "Plugin-version update and signed distribution",
    governance: [
      GovernancePath.TIMELOCK_7D_ADDITION,
      GovernancePath.EXPEDITED_24H_DEPRECATION,
      GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION,
    ],
    surfaces: ["PluginHashRegistry"],
    specSection: "§5",
  },
  {
    number: 4,
    slug: "oracle-onboarding",
    name: "Oracle onboarding",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: ["OracleRegistry", "OracleSchemaRegistry"],
    specSection: "§6",
  },
  {
    number: 5,
    slug: "oracle-rotation",
    name: "Oracle rotation",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: ["OracleRegistry", "OracleSchemaRegistry"],
    specSection: "§7",
  },
  {
    number: 6,
    slug: "qtsp-onboarding-and-root-rotation",
    name: "QTSPRegistry onboarding / root rotation",
    governance: [
      GovernancePath.TIMELOCK_7D_ADDITION,
      GovernancePath.EXPEDITED_24H_DEPRECATION,
      GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION,
    ],
    surfaces: ["QTSPRegistry"],
    specSection: "§7A",
  },
  {
    number: 7,
    slug: "re-key-stanza-addition",
    name: "Re-key / stanza-addition",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: ["SupersededCommitRegistry", "VaultEnvelope"],
    specSection: "§8",
  },
  {
    number: 8,
    slug: "dsl-version-update",
    name: "DSL version update",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: ["DSLVersionRegistry", "ClaimDSL"],
    specSection: "§9",
  },
  {
    number: 9,
    slug: "pda-plus-governance-update",
    name: "PDA+ governance sub-class ceremonies",
    governance: [
      GovernancePath.TIMELOCK_7D_ADDITION,
      GovernancePath.EXPEDITED_24H_DEPRECATION,
      GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION,
    ],
    surfaces: [
      "PDAPlusConfig",
      "TemplateTable",
      "DefaultTable",
      "ValidatorCode",
    ],
    specSection: "§10A",
  },
  {
    number: 10,
    slug: "wasm-predicate-whitelist-update",
    name: "WASM predicate whitelist update",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: ["PDAPlusConfig", "DSLVersionRegistry", "WASMRef"],
    specSection: "§10",
  },
  {
    number: 11,
    slug: "shred-trigger",
    name: "Shred triggering (per-PDA authority + condition)",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION], // per-PDA conditions vary; placeholder
    surfaces: ["ConditionEngine", "ShredRegistry", "G4", "Vault"],
    specSection: "§11",
  },
  {
    number: 12,
    slug: "pause",
    name: "Pause vs shred",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: ["ConditionEngine", "ConditionModules", "Registries", "ShredRegistry"],
    specSection: "§12",
  },
  {
    number: 13,
    slug: "challenge-registry-resolution",
    name: "ChallengeRegistry pause/resolution",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: ["ChallengeRegistry", "G4RefusalRegistry", "ConditionEngine"],
    specSection: "§12.7",
  },
  {
    number: 14,
    slug: "cross-ceremony-invariant-audit",
    name: "Cross-ceremony invariant audit (continuous)",
    governance: [], // continuous, no governance path
    surfaces: ["AllGovernedSurfaces"],
    specSection: "§13",
  },
  {
    number: 15,
    slug: "disaster-recovery-bundle",
    name: "Disaster recovery",
    governance: [
      GovernancePath.EXPEDITED_24H_DEPRECATION,
      GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION,
      GovernancePath.TIMELOCK_7D_ADDITION,
    ],
    surfaces: [
      "G4AuthorityRegistry",
      "PluginHashRegistry",
      "OracleRegistry",
      "EmergencyGovernance",
    ],
    specSection: "§14",
  },
  {
    number: 16,
    slug: "vault-operator-transition",
    name: "Vault operator transition",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: ["VaultRoots", "AuditLogRoots", "RetentionState", "ShredState"],
    specSection: "§14.3",
  },
  {
    number: 17,
    slug: "governance-phase2-transition",
    name: "Governance Phase 2 transition",
    governance: [GovernancePath.TIMELOCK_7D_ADDITION],
    surfaces: [
      "CealisSecurityMultisig",
      "EmergencyGovernance",
      "RoleGrants",
      "GovernancePosture",
    ],
    specSection: "§16.5",
  },
]);

export function findCeremony(slug: string): CeremonyCatalogRow | undefined {
  return CEREMONY_CATALOG.find((c) => c.slug === slug);
}

export function ceremonyAtNumber(n: number): CeremonyCatalogRow | undefined {
  return CEREMONY_CATALOG.find((c) => c.number === n);
}
