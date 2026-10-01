/**
 * Tombstone tuple per S2-6 §0.3 line 27 + §1.4 lines 96–98 (verbatim).
 *
 *   (hash_or_ref, effective_block, tombstone_block)
 *
 * Validity rule: an entry is valid at block `B` iff
 *   effective_block <= B AND (tombstone_block == 0n OR B < tombstone_block).
 *
 * tombstone_block == 0n means "no future expiry".
 */
export interface TombstoneTuple {
  readonly hashOrRef: `0x${string}`;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
}

/**
 * Pure validity check per §1.4. Used by every registry read in M7.
 * @param tuple — the registry entry under test
 * @param atBlock — the block at which validity is being checked
 *                  (commit_block for historical reads per §1.3)
 */
export function isValidAtBlock(
  tuple: TombstoneTuple,
  atBlock: bigint,
): boolean {
  if (tuple.effectiveBlock > atBlock) return false;
  if (tuple.tombstoneBlock === 0n) return true;
  return atBlock < tuple.tombstoneBlock;
}
