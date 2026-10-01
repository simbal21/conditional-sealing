import { describe, it, expect } from "vitest";
import type { Address, Hex } from "viem";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  type CommitAADInput,
  type CommitContextInput,
  ACTIVE_COMMIT_VERSION,
  computeAADDigest,
  computeHCommit,
} from "@cealis/v3-crypto";
import {
  ReKeyStanzaAdditionCeremony,
  generateCeremonyId,
  makeContext,
  proposalHash,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import { makeDryRunRecipientAdapter } from "../../src/adapters/index.js";
import type { CeremonyError } from "../../src/errors/index.js";
import { CeremonyErrorCode } from "../../src/errors/index.js";
import { STANDARD_TIMELOCK_DELAY_SECONDS } from "../../src/multisig/index.js";

const REG: Address = "0xabcdef0000000000000000000000000000000001";
const H = (n: number) => (("0x" + n.toString(16).padStart(2, "0").repeat(32)) as Hex);

/** 32-byte buffer with every byte = `n & 0xff`. Mirrors the H() hex helper. */
const B = (n: number): Uint8Array => new Uint8Array(32).fill(n & 0xff);

function hexToBytes32(hex: Hex): Uint8Array {
  const clean = hex.slice(2);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytes32ToHex(bytes: Uint8Array): Hex {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return ("0x" + hex) as Hex;
}

const OLD_H_COMMIT = H(0x10);
const CIPHERTEXT_DIGEST = B(0x30);
const COMPOSITE_IDENTITY_DIGEST = B(0x80);
const SHRED_AUTHORITY_ID = B(0x90);
const RETENTION_WINDOW = 94_608_000n; // 3 years in seconds
const REVEAL_CHALLENGE_WINDOW = 86_400;
const SHRED_CHALLENGE_WINDOW = 172_800;

/**
 * A complete, spec-valid prior-generation CommitAAD (all 22 fixed-width
 * fields, commit_version = 0x0302). `commit_generation: 1` is the prior
 * generation; the ceremony advances it to N.
 */
function makePriorCommitAad(): CommitAADInput {
  return {
    authorizationId: B(0x01),
    pda_root: B(0x20),
    schema_digest: B(0x02),
    partner_id: B(0x03),
    commit_version: ACTIVE_COMMIT_VERSION,
    subject_commitment_v3: B(0x04),
    sigma_subject_digest: B(0x05),
    recipients_root: B(0x06),
    p15_attestations_root: B(0x07),
    endpoint_attestation_digest: B(0x08),
    conditional_recipients_policy_digest: B(0x09),
    sdMerkleRoot: B(0x0a),
    g3_choice: 1,
    phase: 2,
    composite_identity_type: 0,
    conditional_recipients_stanza_count: 0,
    plugin_version_digest: B(0x0b),
    g4_authority_ref: B(0x0c),
    dsl_version_ref: B(0x0d),
    oracle_references_root: B(0x0e),
    superseded_commit_ref: new Uint8Array(32), // generation 1 → zero
    commit_generation: 1,
  };
}

/**
 * Canonical, byte-exact expected `h_commit_vN` per S2-1 §3.4.1 — computed by
 * the SAME @cealis/v3-crypto helpers the on-chain combiner uses to recompute
 * and match against the SupersededCommitRegistry. This is the closure oracle
 * for TS-CRYPTO-F-05: the vulnerable code computed
 * `keccak256(JSON.stringify(commit_AAD_vN) ‖ envelope_hash)` instead, which
 * never equals this value.
 */
function expectedHCommit(generationN: number): Hex {
  const prior = makePriorCommitAad();
  const commitAadVn: CommitAADInput = {
    ...prior,
    superseded_commit_ref: hexToBytes32(OLD_H_COMMIT),
    commit_generation: generationN,
  };
  const aadDigestN = computeAADDigest(commitAadVn);
  const ctxInput: CommitContextInput = {
    authorizationId: commitAadVn.authorizationId,
    pda_root: commitAadVn.pda_root,
    schema_digest: commitAadVn.schema_digest,
    aad_digest: aadDigestN,
    composite_identity_digest: COMPOSITE_IDENTITY_DIGEST,
    endpoint_attestation_digest: commitAadVn.endpoint_attestation_digest,
    retention_window: RETENTION_WINDOW,
    shred_authority_id: SHRED_AUTHORITY_ID,
    recipients_root: commitAadVn.recipients_root,
    reveal_challenge_window: REVEAL_CHALLENGE_WINDOW,
    shred_challenge_window: SHRED_CHALLENGE_WINDOW,
    g3_choice: commitAadVn.g3_choice,
    phase: commitAadVn.phase,
    commit_version: commitAadVn.commit_version,
  };
  return bytes32ToHex(computeHCommit(ctxInput, CIPHERTEXT_DIGEST));
}

/** The WRONG, pre-fix preimage form. Used to prove the fix changed the value. */
function legacyWrongHCommit(generationN: number): Hex {
  const prior = makePriorCommitAad();
  // The pre-fix code worked off a JSON object with hex-string fields + two
  // overrides; the exact JSON shape is immaterial — any JSON-of-AAD form is a
  // distinct, non-canonical construction. We model the structural class.
  const legacyJson = JSON.stringify({
    ...prior,
    superseded_commit_ref: OLD_H_COMMIT,
    commit_generation: generationN,
  });
  const aadBytes = new TextEncoder().encode(legacyJson);
  const envBytes = CIPHERTEXT_DIGEST;
  const concat = new Uint8Array(aadBytes.length + envBytes.length);
  concat.set(aadBytes, 0);
  concat.set(envBytes, aadBytes.length);
  return bytes32ToHex(keccak_256(concat));
}

function buildCeremony(opts?: { generation?: number; recipients?: number }): ReKeyStanzaAdditionCeremony {
  const recipientCount = opts?.recipients ?? 3;
  return new ReKeyStanzaAdditionCeremony({
    supersededRegistryAddress: REG,
    oldHCommit: OLD_H_COMMIT,
    commitGenerationN: opts?.generation ?? 2,
    priorCommitAad: makePriorCommitAad(),
    compositeIdentityDigest: COMPOSITE_IDENTITY_DIGEST,
    retentionWindow: RETENTION_WINDOW,
    shredAuthorityId: SHRED_AUTHORITY_ID,
    revealChallengeWindow: REVEAL_CHALLENGE_WINDOW,
    shredChallengeWindow: SHRED_CHALLENGE_WINDOW,
    ciphertextDigestN: CIPHERTEXT_DIGEST,
    addEntryCalldata: H(0x40),
    salt: H(0x50),
    recipientSet: Array.from({ length: recipientCount }, (_, i) => ({
      recipientId: H(0x60 + i),
    })),
    lineageRoot: H(0x70),
    recipientAdapter: makeDryRunRecipientAdapter().adapter,
  });
}

describe("re-key-stanza-addition (§8)", () => {
  it("dry-run reaches complete with CommitSuperseded emitted", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = buildCeremony();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
    expect(outcome.emittedEvents).toContain("CommitSuperseded");
    expect(outcome.stagesReached).toContain("complete");
  });

  // TS-CRYPTO-F-05 closure test (HIGH).
  //
  // The ceremony's h_commit_vN MUST equal the canonical S2-1 §3.4.1 340-byte
  // fixed-width preimage that the on-chain combiner recomputes from the 15
  // fields when walking SupersededCommitRegistry at reveal. We reconstruct
  // the proposalHash payload using an INDEPENDENTLY-computed canonical
  // h_commit (via the same @cealis/v3-crypto computeAADDigest + computeHCommit
  // the combiner uses) and assert the ceremony's proposalHash matches.
  //
  // Against the vulnerable code (keccak256(JSON.stringify(commit_AAD_vN) ‖
  // envelope_hash) — no TAG_COMMIT_V3, no SCALE, 12 of 15 fields absent) the
  // ceremony's newHCommit is a different value, so the proposalHash differs
  // and this assertion FAILS. Against the fix it PASSES.
  it("TS-CRYPTO-F-05: h_commit_vN is the byte-exact S2-1 §3.4.1 340-byte preimage, not JSON-of-AAD", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = buildCeremony({ generation: 2 });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    const p = await ceremony.proposal({ context: ctx, chain });

    const canonicalHCommit = expectedHCommit(2);
    const expectedProposalHash = proposalHash({
      ceremony: ceremony.slug,
      oldHCommit: OLD_H_COMMIT,
      commitGenerationN: 2,
      newHCommit: canonicalHCommit,
    });
    // The ceremony bound the canonical h_commit into its proposal.
    expect(p.proposalHash).toBe(expectedProposalHash);

    // And the canonical form is genuinely distinct from the pre-fix JSON form,
    // so the test cannot pass against the vulnerable construction.
    const wrongHCommit = legacyWrongHCommit(2);
    expect(canonicalHCommit).not.toBe(wrongHCommit);
    const wrongProposalHash = proposalHash({
      ceremony: ceremony.slug,
      oldHCommit: OLD_H_COMMIT,
      commitGenerationN: 2,
      newHCommit: wrongHCommit,
    });
    expect(p.proposalHash).not.toBe(wrongProposalHash);
  });

  it("computes h_commit_vN deterministically — equal inputs → equal proposalHash", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony1 = buildCeremony();
    const ceremony2 = buildCeremony();
    const ctx1 = makeContext({
      ceremonyId: generateCeremonyId(ceremony1.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony1.slug,
    });
    const ctx2 = makeContext({
      ceremonyId: generateCeremonyId(ceremony2.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony2.slug,
    });
    const p1 = await ceremony1.proposal({ context: ctx1, chain });
    const p2 = await ceremony2.proposal({ context: ctx2, chain });
    expect(p1.proposalHash).toBe(p2.proposalHash);
  });

  it("changing commitGenerationN changes h_commit_vN (commit_generation is in the SCALE preimage)", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const cGen2 = buildCeremony({ generation: 2 });
    const cGen3 = buildCeremony({ generation: 3 });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(cGen2.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: cGen2.slug,
    });
    const p2 = await cGen2.proposal({ context: ctx, chain });
    const p3 = await cGen3.proposal({ context: ctx, chain });
    expect(p2.proposalHash).not.toBe(p3.proposalHash);
    // And each matches its independently-computed canonical oracle.
    expect(p2.proposalHash).toBe(
      proposalHash({ ceremony: cGen2.slug, oldHCommit: OLD_H_COMMIT, commitGenerationN: 2, newHCommit: expectedHCommit(2) }),
    );
    expect(p3.proposalHash).toBe(
      proposalHash({ ceremony: cGen3.slug, oldHCommit: OLD_H_COMMIT, commitGenerationN: 3, newHCommit: expectedHCommit(3) }),
    );
  });

  it("invalid commitGenerationN (0 or negative) → REGISTRY_COLLISION at proposal", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = buildCeremony({ generation: 0 });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    let caught: CeremonyError | undefined;
    try {
      await ceremony.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(caught?.code).toBe(CeremonyErrorCode.REGISTRY_COLLISION);
  });

  it("malformed prior CommitAAD (wrong commit_version) → REGISTRY_COLLISION at proposal", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const badAad: CommitAADInput = { ...makePriorCommitAad(), commit_version: 0x0301 };
    const ceremony = new ReKeyStanzaAdditionCeremony({
      supersededRegistryAddress: REG,
      oldHCommit: OLD_H_COMMIT,
      commitGenerationN: 2,
      priorCommitAad: badAad,
      compositeIdentityDigest: COMPOSITE_IDENTITY_DIGEST,
      retentionWindow: RETENTION_WINDOW,
      shredAuthorityId: SHRED_AUTHORITY_ID,
      revealChallengeWindow: REVEAL_CHALLENGE_WINDOW,
      shredChallengeWindow: SHRED_CHALLENGE_WINDOW,
      ciphertextDigestN: CIPHERTEXT_DIGEST,
      addEntryCalldata: H(0x40),
      salt: H(0x50),
      recipientSet: [{ recipientId: H(0x60) }],
      lineageRoot: H(0x70),
      recipientAdapter: makeDryRunRecipientAdapter().adapter,
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    let caught: CeremonyError | undefined;
    try {
      await ceremony.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(caught?.code).toBe(CeremonyErrorCode.REGISTRY_COLLISION);
  });

  it("recipient adapter call signature is honored (§8.10)", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const dryRecip = makeDryRunRecipientAdapter();
    const ceremony = new ReKeyStanzaAdditionCeremony({
      supersededRegistryAddress: REG,
      oldHCommit: OLD_H_COMMIT,
      commitGenerationN: 2,
      priorCommitAad: makePriorCommitAad(),
      compositeIdentityDigest: COMPOSITE_IDENTITY_DIGEST,
      retentionWindow: RETENTION_WINDOW,
      shredAuthorityId: SHRED_AUTHORITY_ID,
      revealChallengeWindow: REVEAL_CHALLENGE_WINDOW,
      shredChallengeWindow: SHRED_CHALLENGE_WINDOW,
      ciphertextDigestN: CIPHERTEXT_DIGEST,
      addEntryCalldata: H(0x40),
      salt: H(0x50),
      recipientSet: [{ recipientId: H(0x60) }, { recipientId: H(0x61) }],
      lineageRoot: H(0x70),
      recipientAdapter: dryRecip.adapter,
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    await ceremony.run({ context: ctx, chain });
    expect(dryRecip.calls).toHaveLength(1);
    expect(dryRecip.calls[0]?.recipientCount).toBe(2);
    expect(dryRecip.calls[0]?.commitGeneration).toBe(2);
  });

  it("live happy path executes after timelock", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    chain.pendingEvents.push({ eventName: "CommitSuperseded" });
    const orig = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (a) => {
      const r = await orig(a);
      chain.advanceSeconds(BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60));
      return r;
    };
    const ceremony = buildCeremony();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
    expect(outcome.emittedEvents).toContain("CommitSuperseded");
  });
});
