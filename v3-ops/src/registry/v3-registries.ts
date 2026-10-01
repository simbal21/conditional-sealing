import {
  FIVE_V3_REGISTRIES,
  isV3Registry,
  type V3Registry,
} from "../catalog/registries.js";

/**
 * Deprecation flag state per S2-6 §13.6 + §13.7. The flag uses the
 * asymmetric governance discipline from S2-2 §9. Auto-clear happens
 * permissionlessly via `triggerAutoClear(entry_id)` after 72h if no
 * matching disclosure was published.
 */
export interface DeprecationFlag {
  readonly registryName: V3Registry;
  readonly entryId: `0x${string}`;
  readonly setBlock: bigint;
  readonly setBy: `0x${string}`; // address of the actor who set it
  readonly reasonCode: number;
  readonly disclosureCid: string | null;
  readonly disclosureCommitHash: `0x${string}` | null;
  readonly autoClearedBlock: bigint | null; // 0n if still set
}

/**
 * Per-registry V3 governance metadata. Maps the 5-element registry set to
 * the surface they read/write on-chain. The slot here is a logical
 * placeholder; M2 ABI loaders fill the real contract addresses at runtime
 * (via `src/m2-imports.ts`).
 */
export const V3_REGISTRY_METADATA: Readonly<
  Record<V3Registry, { specSection: string; contractSlot: string }>
> = Object.freeze({
  PluginHashRegistry: {
    specSection: "S2-2 §9.5",
    contractSlot: "PluginHashRegistry",
  },
  G4AuthorityRegistry: {
    specSection: "S2-2 §9.6",
    contractSlot: "G4AuthorityRegistry",
  },
  DSLVersionRegistry: {
    specSection: "S2-2 §9.7",
    contractSlot: "DSLVersionRegistry",
  },
  OracleRegistry: {
    specSection: "S2-2 §9.8",
    contractSlot: "OracleRegistry",
  },
  QTSPRegistry: {
    specSection: "S2-2 §9.9",
    contractSlot: "QTSPRegistry",
  },
});

export { FIVE_V3_REGISTRIES, isV3Registry, type V3Registry };
