/**
 * The FIVE Cealis-governed V3 registries per S2-6 §2 line 147 + §13.6.
 * Verbatim list — adjacent surfaces (OracleSchemaRegistry, LitV3Assignment,
 * GateRecipientPubkeyRegistry, SupersededCommitRegistry, ChallengeRegistry,
 * ShredRegistry, G4RefusalRegistry, DisclosureRegistry,
 * DisclosureRevocationRegistry) are NOT counted as the five.
 *
 * Foundation test `v3-registry-set.test.ts` asserts (a) set size === 5,
 * (b) set membership matches verbatim names, (c) none of the adjacent
 * surfaces are members.
 */
export const FIVE_V3_REGISTRIES = Object.freeze([
  "PluginHashRegistry",
  "G4AuthorityRegistry",
  "DSLVersionRegistry",
  "OracleRegistry",
  "QTSPRegistry",
] as const);

export type V3Registry = (typeof FIVE_V3_REGISTRIES)[number];

/**
 * Adjacent registry surfaces that exist on-chain but are NOT counted as
 * one of the five Cealis-governed registries. Listed here for foundation
 * test cross-check.
 */
export const ADJACENT_REGISTRY_SURFACES = Object.freeze([
  "OracleSchemaRegistry",
  "LitV3Assignment",
  "GateRecipientPubkeyRegistry",
  "SupersededCommitRegistry",
  "ChallengeRegistry",
  "ShredRegistry",
  "G4RefusalRegistry",
  "DisclosureRegistry",
  "DisclosureRevocationRegistry",
  "PartnerRegistry",
] as const);

export function isV3Registry(s: string): s is V3Registry {
  return (FIVE_V3_REGISTRIES as readonly string[]).includes(s);
}
