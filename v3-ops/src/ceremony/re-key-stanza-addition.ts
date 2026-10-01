import type { Address, Hex } from "viem";
import {
  type CommitAADInput,
  type CommitContextInput,
  computeAADDigest,
  computeHCommit,
} from "@cealis/v3-crypto";
import { Ceremony, delayForPath, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import type { RecipientParticipationAdapter } from "../adapters/index.js";

/**
 * §8 — Re-key / stanza-addition (P21).
 *
 * Re-key is additive at the stanza layer. It adds a new generation of
 * stanzas under fresher primitives. It does NOT touch payload bytes,
 * regenerate DEK, mutate the original `h_commit`, or treat σ as entropy.
 * It preserves Shamir share values and `file_key` across generations.
 *
 * §8.5: `commit_AAD_vN` differs from prior generations only in
 *   - `superseded_commit_ref = oldHCommit`
 *   - `commit_generation = N`
 * `h_commit_vN` is the canonical S2-1 §3.4.1 340-byte fixed-width keccak
 * preimage (`TAG_COMMIT_V3 ‖ authorizationId ‖ pda_root ‖ schema_digest ‖
 * ciphertext_digest_N ‖ aad_digest_N ‖ composite_identity_digest ‖
 * endpoint_attestation_digest_N ‖ retention_window ‖ shred_authority_id ‖
 * recipients_root ‖ reveal_challenge_window ‖ shred_challenge_window ‖
 * g3_choice ‖ phase ‖ commit_version`) where
 * `aad_digest_N = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD_N))` and
 * `ciphertext_digest_N = keccak256(age_envelope_N)`. The byte math is owned
 * by `@cealis/v3-crypto` (`computeHCommit` / `computeAADDigest`); this
 * ceremony assembles the field set and delegates — it never reimplements the
 * preimage layout. This is the value the combiner recomputes and matches
 * against the on-chain SupersededCommitRegistry at reveal time, so any drift
 * from the canonical construction breaks every re-keyed reveal path.
 *
 * §8.10: recipient participation is interface-stubbed (`RecipientParticipationAdapter`).
 * Real UX / vendor coordination / queue management lives in S3-1.
 *
 * §8.6: combiner reads SupersededCommitRegistry walking generation by
 * generation. M7 ceremony enforces the registry write under
 * `REKEY_GOVERNANCE_ROLE` after the 7-day timelock.
 */
export interface ReKeyStanzaAdditionInput {
  readonly supersededRegistryAddress: Address;
  readonly oldHCommit: Hex;
  readonly commitGenerationN: number;
  /**
   * Parsed prior generation `CommitAAD` — all 22 fixed-width fields per
   * S2-1 §4. Generation N reuses every field unchanged except the two §8.5
   * overrides applied below (`superseded_commit_ref`, `commit_generation`),
   * so `aad_digest_N` can be derived byte-exactly via `computeAADDigest`.
   */
  readonly priorCommitAad: CommitAADInput;
  /**
   * The five `CommitContextInput` fields that are NOT carried inside the
   * `CommitAAD` SCALE struct (S2-1 §3.4.1 vs §4): `composite_identity_digest`
   * (§3.4.2), `retention_window`, `shred_authority_id`, `reveal_challenge_window`,
   * `shred_challenge_window`. These are stable across generations for a given
   * commitment.
   */
  readonly compositeIdentityDigest: Uint8Array;
  readonly retentionWindow: bigint;
  readonly shredAuthorityId: Uint8Array;
  readonly revealChallengeWindow: number;
  readonly shredChallengeWindow: number;
  /**
   * `ciphertext_digest_N = keccak256(age_envelope_N)` — the keccak of the
   * post-re-key serialized envelope bytes. Slot 4 of the 340-byte preimage.
   */
  readonly ciphertextDigestN: Uint8Array;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
  /** Recipient set for §8.4 fresh σ collection. */
  readonly recipientSet: ReadonlyArray<{ readonly recipientId: Hex }>;
  /** Lineage root for §8.4 fresh σ collection over the lineage context. */
  readonly lineageRoot: Hex;
  readonly recipientAdapter: RecipientParticipationAdapter;
}

export class ReKeyStanzaAdditionCeremony extends Ceremony {
  override readonly slug = "re-key-stanza-addition";
  override readonly specSection = "§8";
  override readonly catalogRowNumber = 7;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  private readonly input: ReKeyStanzaAdditionInput;
  private hCommitVn: Hex | null = null;
  private ackDigests: ReadonlyArray<{
    readonly recipientId: Hex;
    readonly recipientPubkey: Hex;
    readonly ackDigest: Hex;
  }> | null = null;

  constructor(input: ReKeyStanzaAdditionInput) {
    super();
    this.input = input;
  }

  async proposal(_args: CeremonyRunArgs): Promise<{
    proposalHash: Hex;
    target: Address;
    data: Hex;
    salt: Hex;
  }> {
    if (this.input.commitGenerationN <= 0) {
      throw new CeremonyError(
        CeremonyErrorCode.REGISTRY_COLLISION,
        "proposal",
        { ceremonySlug: this.slug },
      );
    }

    // §8.5 commit_AAD_vN construction: prior CommitAAD with exactly the two
    // field overrides applied. `superseded_commit_ref` points at the prior
    // generation's final h_commit; `commit_generation` advances to N.
    const oldHCommitBytes = hexToBytes32(this.input.oldHCommit);
    const commitAadVn: CommitAADInput = {
      ...this.input.priorCommitAad,
      superseded_commit_ref: oldHCommitBytes,
      commit_generation: this.input.commitGenerationN,
    };

    // h_commit_vN per S2-1 §3.4.1 — byte-exact 340-byte fixed-width preimage.
    // The encoding (TAG_COMMIT_V3 prefix, SCALE(commit_AAD) → aad_digest,
    // fixed-width field order, BE integer widths) is owned by @cealis/v3-crypto.
    // We assemble the field set; computeAADDigest + computeHCommit own the
    // byte math. Field validation (bytes32 lengths, integer ranges,
    // commit_version === 0x0302) is enforced inside those helpers and throws
    // a CommitAAD/CommitContext validation error on malformed input, which we
    // surface as a REGISTRY_COLLISION at proposal stage.
    let hCommitBytes: Uint8Array;
    try {
      const aadDigestN = computeAADDigest(commitAadVn);
      const ctxInput: CommitContextInput = {
        authorizationId: commitAadVn.authorizationId,
        pda_root: commitAadVn.pda_root,
        schema_digest: commitAadVn.schema_digest,
        aad_digest: aadDigestN,
        composite_identity_digest: this.input.compositeIdentityDigest,
        endpoint_attestation_digest: commitAadVn.endpoint_attestation_digest,
        retention_window: this.input.retentionWindow,
        shred_authority_id: this.input.shredAuthorityId,
        recipients_root: commitAadVn.recipients_root,
        reveal_challenge_window: this.input.revealChallengeWindow,
        shred_challenge_window: this.input.shredChallengeWindow,
        g3_choice: commitAadVn.g3_choice,
        phase: commitAadVn.phase,
        commit_version: commitAadVn.commit_version,
      };
      hCommitBytes = computeHCommit(ctxInput, this.input.ciphertextDigestN);
    } catch (e) {
      throw new CeremonyError(
        CeremonyErrorCode.REGISTRY_COLLISION,
        "proposal",
        { ceremonySlug: this.slug, stage: (e as Error).message },
      );
    }
    this.hCommitVn = bytes32ToHex(hCommitBytes);

    const hash = proposalHash({
      ceremony: this.slug,
      oldHCommit: this.input.oldHCommit,
      commitGenerationN: this.input.commitGenerationN,
      newHCommit: this.hCommitVn,
    });
    return {
      proposalHash: hash,
      target: this.input.supersededRegistryAddress,
      data: this.input.addEntryCalldata,
      salt: this.input.salt,
    };
  }

  async queue(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const delay = delayForPath(this.governancePath);
    const { opId, txHash } = await args.chain.scheduleTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      salt: p.salt,
      delaySeconds: delay,
    });
    this.opId = opId;
    this.recordTx(txHash);
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "queue",
      message: "rekey_proposal_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        oldHCommit: this.input.oldHCommit,
        newHCommit: this.hCommitVn!,
        commitGenerationN: this.input.commitGenerationN,
        txHash,
        governancePath: this.governancePath,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    // §8.4 fresh σ collection — interface-stubbed call, returns only
    // public participation evidence (pubkey + ack digest), NOT σ bytes.
    this.ackDigests = await this.input.recipientAdapter.collectFreshSigma({
      commitGeneration: this.input.commitGenerationN,
      lineageRoot: this.input.lineageRoot,
      recipientSet: this.input.recipientSet,
    });

    for (const ack of this.ackDigests) {
      await this.logger!.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "execute",
        message: "recipient_ack",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          recipientId: ack.recipientId,
          recipientPubkey: ack.recipientPubkey,
          ackDigest: ack.ackDigest,
        },
      });
    }

    if (args.context.dryRun) {
      this.recordEvent("CommitSuperseded");
      await this.logger!.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "execute",
        message: "rekey_dry_run_simulated",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
          dryRun: true,
        },
      });
      return;
    }

    // Real execute requires REKEY_GOVERNANCE_ROLE — Phase F integration
    // tests grant this via Anvil fork. The TimelockController.execute call
    // here delivers the role-gated SupersededCommitRegistry write.
    const { txHash, events } = await args.chain.executeTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      salt: p.salt,
    });
    this.recordTx(txHash);
    for (const ev of events) this.recordEvent(ev.eventName);
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "execute",
      message: "rekey_executed",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        oldHCommit: this.input.oldHCommit,
        newHCommit: this.hCommitVn!,
        commitGenerationN: this.input.commitGenerationN,
        txHash,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const expected: CeremonyEventName = "CommitSuperseded";
    if (!this.emittedEvents.includes(expected)) {
      throw new CeremonyError(
        CeremonyErrorCode.REGISTRY_COLLISION,
        "verify",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
        },
      );
    }
    if (this.ackDigests === null || this.ackDigests.length !== this.input.recipientSet.length) {
      throw new CeremonyError(
        CeremonyErrorCode.QUORUM_MISSING,
        "verify",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
        },
      );
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "verify",
      message: "rekey_lineage_anchored",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        oldHCommit: this.input.oldHCommit,
        newHCommit: this.hCommitVn!,
        commitGenerationN: this.input.commitGenerationN,
        proposalHash: p.proposalHash,
      },
    });
  }
}

function hexToBytes32(hex: Hex): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length !== 64) {
    throw new Error(`expected 32-byte hex (64 chars), got ${clean.length}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytes32ToHex(bytes: Uint8Array): Hex {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return ("0x" + hex) as Hex;
}
