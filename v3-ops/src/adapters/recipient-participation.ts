import type { Hex } from "viem";

/**
 * Recipient participation adapter interface stub per S2-6 §8.10. The actual
 * UX/coordination flow lives in S3-1 — M7 calls
 * `recipientParticipationAdapter.collectFreshSigma(...)` during re-key
 * Phase C. Phase A locks the type shape; ceremony scripts in Phase C
 * import this interface and a real S3-1 implementation drops in later.
 *
 * NORMATIVE invariant: σ values cross the re-key boundary ONLY inside the
 * hardened combiner context per §8.10. No retry queue, log, crash dump,
 * diagnostic artifact, or audit event may contain σ bytes, share bytes,
 * DEK, or plaintext.
 *
 * The return type intentionally exposes only PUBLIC pubkey lookups +
 * generation bookkeeping; the σ values themselves never leak through this
 * interface.
 */
export interface RecipientParticipationAdapter {
  /**
   * Coordinate fresh σ generation from each recipient over the existing
   * lineage root context under the newer primitive or authority
   * generation. Implementations MUST keep σ bytes inside the hardened
   * combiner; this method returns only public participation evidence
   * (recipient pubkey + acknowledgement digest), NOT the σ values.
   */
  collectFreshSigma(opts: {
    readonly commitGeneration: number;
    readonly lineageRoot: Hex;
    readonly recipientSet: ReadonlyArray<{ readonly recipientId: Hex }>;
  }): Promise<
    ReadonlyArray<{
      readonly recipientId: Hex;
      readonly recipientPubkey: Hex;
      readonly ackDigest: Hex;
    }>
  >;
}

/**
 * Dry-run adapter — records calls + returns a deterministic fake ack
 * digest. Phase C tests use this for `--dry-run` re-key invocations.
 */
export function makeDryRunRecipientAdapter(): {
  readonly adapter: RecipientParticipationAdapter;
  readonly calls: ReadonlyArray<{
    readonly commitGeneration: number;
    readonly lineageRoot: Hex;
    readonly recipientCount: number;
  }>;
} {
  const calls: {
    commitGeneration: number;
    lineageRoot: Hex;
    recipientCount: number;
  }[] = [];
  return {
    adapter: {
      async collectFreshSigma(opts) {
        calls.push({
          commitGeneration: opts.commitGeneration,
          lineageRoot: opts.lineageRoot,
          recipientCount: opts.recipientSet.length,
        });
        return opts.recipientSet.map((r) => ({
          recipientId: r.recipientId,
          recipientPubkey: ("0x" + "aa".repeat(32)) as Hex,
          ackDigest: ("0x" + "bb".repeat(32)) as Hex,
        }));
      },
    },
    get calls() {
      return calls;
    },
  };
}
