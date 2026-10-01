import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import { isValidAtBlock, type TombstoneTuple } from "../types/tombstone.js";

/**
 * At-commit-block reading discipline per S2-6 §1.3 NORMATIVE.
 *
 * Every verifier reads registry and assignment state at the block bound to
 * the commitment's authorization context, not at current head. A later
 * plugin, G4 key, DSL, oracle, QTSP, Lit assignment, or G3 committee
 * rotation MUST NOT alter verification for an already committed object.
 *
 * Foundation test `at-commit-block-read.test.ts` covers
 *   (a) historical block returns the historical entry,
 *   (b) current-head ceremony call attempting omitted `commitBlock` throws
 *       `CEREMONY_ERR_COMMIT_BLOCK_MISMATCH`.
 */

/**
 * Abstract registry contract reader. Implementations live in
 * `src/m2-imports.ts` (viem-backed) and tests (in-memory fixture).
 */
export interface RegistryReader {
  readonly registryName: string;
  /**
   * Return the entry tuple effective at `atBlock` for `entryRef`, or
   * undefined if no entry has effective_block <= atBlock.
   */
  getEntryAt(
    entryRef: `0x${string}`,
    atBlock: bigint,
  ): Promise<TombstoneTuple | undefined>;
}

/**
 * Read a registry entry at the historical `commitBlock`. Throws
 * `CEREMONY_ERR_COMMIT_BLOCK_MISMATCH` if `commitBlock` is missing / zero,
 * `CEREMONY_ERR_TOMBSTONE_CONFLICT` if the entry exists but is invalid at
 * that block (tombstoned or not yet effective).
 */
export async function readEntryAt(
  reader: RegistryReader,
  entryRef: `0x${string}`,
  commitBlock: bigint,
): Promise<TombstoneTuple> {
  if (commitBlock === 0n) {
    throw new CeremonyError(
      CeremonyErrorCode.COMMIT_BLOCK_MISMATCH,
      "verify",
      {
        registryName: reader.registryName,
        entryId: entryRef,
        commitBlock,
      },
    );
  }
  const tuple = await reader.getEntryAt(entryRef, commitBlock);
  if (tuple === undefined) {
    throw new CeremonyError(
      CeremonyErrorCode.REGISTRY_COLLISION,
      "verify",
      {
        registryName: reader.registryName,
        entryId: entryRef,
        commitBlock,
      },
    );
  }
  if (!isValidAtBlock(tuple, commitBlock)) {
    throw new CeremonyError(
      CeremonyErrorCode.TOMBSTONE_CONFLICT,
      "verify",
      {
        registryName: reader.registryName,
        entryId: entryRef,
        commitBlock,
        effectiveBlock: tuple.effectiveBlock,
        tombstoneBlock: tuple.tombstoneBlock,
      },
    );
  }
  return tuple;
}
