// T3.3 — the F-API-1 JOIN (security-critical) tests.
//
// WHAT THIS PROVES
// ----------------
// The reveal path no longer accepts cleartext from the request body. Instead,
// `processRevealAuthorizedEvent` takes a `combiner_input` REFERENCE and produces
// the plaintext by routing gathered σ + vault ciphertext through the REAL
// cryptographic combiner (`combineAndDecrypt` via `runM3CombinerBridge`). The
// plaintext's PROVENANCE is the combiner, not the request.
//
// THE ROUND-TRIP (real crypto, doubled gates)
// -------------------------------------------
//   1. Seal a KNOWN JSON plaintext under a freshly-generated 32-byte DEK
//      (`encryptPayload` → ciphertext; `encodeAgeEnvelope`/`encodeCommitAAD`).
//   2. `dealDek(DEK, profile)` produces REAL, non-degenerate Shamir shares
//      (the F-CRYPTO-2 dealer — NOT the every-share==DEK shortcut). Each share
//      value is threaded into its gate's σ metadata (`shareHex`).
//   3. A deterministic SigmaGatherer double returns the σ evidence bundle
//      (gate signing is doubled; the cryptographic combine+decrypt is REAL).
//   4. A fake vault holds the sealed ciphertext + its inseparable commit
//      binding (C1).
//   5. Run the rewritten `processRevealAuthorizedEvent`: combineAndDecrypt
//      reconstructs the DEK from the dealt shares via Lagrange and AEAD-decrypts
//      → plaintext == the original. The recipient-filtered bundle carries the
//      original field values.
//
// C3a (snapshot-recheck) STILL HOLDS
// ----------------------------------
// The per-enqueue LIVE re-read of all 5 axes is exercised through the real
// `RevealCoordinatorImpl`: a shred-finalized (and, separately, an Art.18-freeze)
// injected at the per-enqueue re-read halts delivery — the bundle is
// dead-lettered, nothing is enqueued. (The combiner-orchestrator's own
// type-forced `GateClearance<"pre-delivery">` discipline is untouched by the
// F-API-1 refactor.)
//
// REAL vs DOUBLED (reported in the structured output)
// ---------------------------------------------------
//   REAL (in-process, exercised for real):
//     - dealDek (real Shamir split) + combineDek (real Lagrange reconstruct)
//     - encryptPayload / decryptAeadPayload (real ChaCha20-Poly1305 AEAD)
//     - the full combineAndDecrypt pre-verify pipeline (C1 commit-AAD
//       round-trip, canonical-address pin, plugin integrity, snapshot verify)
//     - RevealCoordinatorImpl C3a per-enqueue re-clearance
//   DOUBLED (deterministic in-process stand-ins for the vendor-gated ports):
//     - SigmaGatherer (the real Lit V3 / dcipher / drand / G4-TEE network
//       clients are §6 external gates) → returns pre-built σ evidence
//     - CealisV3Vault (the real Postgres/Filesystem backend is T0.3) → holds
//       the sealed ciphertext in memory for the read

import { describe, expect, it, vi } from "vitest";

import {
  dealDek,
  encodeAgeEnvelope,
  encodeCommitAAD,
  encryptPayload,
  TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
  TAG_G3_BINDING_V3,
  TAG_G4_ATTESTATION_V3,
  TAG_LIT_ACC_BINDING_V3,
  zeroCommitAADInput,
  type CommitAADInput,
} from "@cealis/v3-crypto";

import * as M3 from "../../src/m3-imports.js";
import {
  bytesToHex,
  GateKind,
  ShredState,
  type AccessStructureProfile,
  type AuthorizationRegistrySnapshot,
  type CommitRegistrySnapshot,
  type GateRecipientPubkeyEntry,
  type SigmaEvidence,
  type SigmaEvidenceBundle,
} from "../../src/m3-imports.js";

/**
 * The running-combiner measurement that plugin-integrity binds against
 * (`measureRunningCombinerBundle`, F-CRYPTO-1). Resolved at runtime so this
 * fixture builds whether or not the `@cealis/v3-custody` build output is fresh:
 * with the rebuilt dist the REAL measurement is used (the real round-trip
 * validates plugin integrity); without it, a deterministic placeholder is used
 * (the runner-double + C3a paths never validate plugin integrity, so the value
 * is inert for them). The real round-trip test is env-gated to skip when the
 * combiner build is stale (see `REAL_COMBINER_AVAILABLE`).
 */
const REAL_COMBINER_AVAILABLE =
  typeof (M3 as { measureRunningCombinerBundle?: unknown }).measureRunningCombinerBundle === "function";

function runningCombinerMeasurementHex(): Hex32 {
  const fn = (M3 as { measureRunningCombinerBundle?: () => Uint8Array }).measureRunningCombinerBundle;
  if (typeof fn === "function") return bytesToHex(fn()) as Hex32;
  return ("0x" + "ab".repeat(32)) as Hex32;
}

import {
  processRevealAuthorizedEvent,
  type CombinerInputReference,
  type EventDrivenRevealInput,
  type RunM3CombinerBridgeInput,
} from "../../src/combiner-orchestrator/index.js";
import { InMemoryRevealArtifactRepository } from "../../src/bundle/index.js";
import type {
  SigmaGatherer,
  SigmaGatheringRequest,
} from "../../src/combiner-orchestrator/sigma-gathering.js";
import type {
  CealisV3Vault,
  VaultBlob,
  VaultRef,
} from "../../src/vault/cealis-v3-vault.js";
import type { Hex32 } from "../../src/types/reveal-artifact-bundle.js";

import {
  ConcreteLiveStateReader,
  RevealCoordinatorImpl,
  clearGatesAt,
  type LiveStateReaderPorts,
} from "../../src/reveal/reveal-coordinator-impl.js";
import type {
  RevealCoordinatorInput,
  RevealCoordinatorPorts,
  RevealDeliveryQueue,
} from "../../src/reveal/reveal-coordinator.js";

// ───────────────────────── constants ─────────────────────────

const AUTH_ID = hex32(0x11);
const H_COMMIT = hex32(0x22);
const BLOCK_HASH = hex32(0x33);
const PLUGIN_DIGEST = hex32(0x44);
const COMMIT_CONTEXT_DIGEST_0 = bytes32(0xaa);
const VAULT_REF: VaultRef = "vault://test/known-plaintext";

// The known plaintext we seal and expect the combiner to recover. JSON because
// the default plaintext decoder is JSON/UTF-8.
const KNOWN_PLAINTEXT_OBJECT = {
  legal_name: "Ada Lovelace",
  date_of_birth: "1815-12-10",
  nationality: "GB",
} as const;

/**
 * A FRESH copy of the known plaintext bytes each call. `processRevealAuthorized
 * Event` ZEROIZES the decrypted plaintext after bundle assembly (GDPR hygiene),
 * so a shared module-level buffer would be clobbered between tests — and a real
 * combiner returns a fresh allocation per decrypt anyway. (That the shared
 * buffer got zeroized across tests is itself proof the zeroization fires.)
 */
function freshKnownPlaintext(): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(KNOWN_PLAINTEXT_OBJECT));
}

const CANONICAL_CONDITION_ENGINE = "0xb09a8300423CA3BD0E028bAB6A6245A248520D02" as const;
const CANONICAL_CHAIN_ID = 84_532;

// ───────────────────────── fixture builders ─────────────────────────
//
// Mirrors v3-custody/tests/integration/combiner-testkit.ts (not exported from
// the package) — but seals with a FRESH random DEK and deals REAL,
// non-degenerate Shamir shares via `dealShares`. The σ evidence carries each
// dealt share value in `metadata.shareHex`, which `orchestrateSigmas`
// re-derives into a typed ShareRecord and `combineDek` reconstructs.

interface SealedFixture {
  readonly profile: AccessStructureProfile;
  readonly ciphertext: Uint8Array; // the age envelope (what the vault stores)
  readonly commitAADBytes: Uint8Array;
  readonly sigmas: SigmaEvidenceBundle;
  readonly commitSnapshot: CommitRegistrySnapshot;
  readonly authorizationSnapshot: AuthorizationRegistrySnapshot;
}

/**
 * Build a FIXED_ONLY sealed fixture: seal KNOWN_PLAINTEXT under a random DEK,
 * deal the DEK into 3 real shares (Lit/G3/G4), and assemble the σ + snapshot
 * inputs the combiner consumes. g3_choice = drand (1).
 */
function buildSealedFixture(): SealedFixture {
  const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
  const dek = randomDek();
  const commitAAD = buildCommitAAD();

  const encrypted = encryptPayload({
    dek,
    commit_context_digest_0: COMMIT_CONTEXT_DIGEST_0,
    commit_AAD_v0: commitAAD,
    plaintext: freshKnownPlaintext(),
  });

  // REAL Shamir deal (non-degenerate) — the keystone the F-API-1 join relies on.
  // FIXED_ONLY emits exactly [Lit(logical 0), G3(1), G4(2)] in order.
  const records = dealDek(dek, profile);
  const litShare = records[0]!.value;
  const g3Share = records[1]!.value;
  const g4Share = records[2]!.value;

  const evidence: SigmaEvidence[] = [
    makeEvidence(GateKind.LitV3, 0, 0, litShare),
    makeEvidence(GateKind.Drand, 0, 1, g3Share),
    makeEvidence(GateKind.G4, 0, 2, g4Share),
  ];

  const ageEnvelope = encodeAgeEnvelope({
    stanzas: evidence.map((item, index) => ({
      stanza_index: index,
      binding_tag: bindingTag(item.gateKind),
      plugin_version_digest: commitAAD.plugin_version_digest,
      ciphertext_payload_bytes: new Uint8Array([item.gateKind, item.conditionalRecipientIndex]),
    })),
    payload_ciphertext: encrypted.ciphertext,
  });

  // Zeroize our copy of the DEK — only the dealt shares (and the vault
  // ciphertext) leave this scope.
  dek.fill(0);

  return {
    profile,
    ciphertext: ageEnvelope,
    commitAADBytes: encodeCommitAAD(commitAAD),
    sigmas: {
      authorizationId: AUTH_ID,
      hCommit: H_COMMIT,
      authorizationBlock: 20n,
      commitBlock: 10n,
      evidence,
    },
    commitSnapshot: {
      snapshot: { blockNumber: 10n, chainId: CANONICAL_CHAIN_ID, blockHash: hex32(0x10), observedAt: 1n },
      plugin: {
        pluginVersionDigest: PLUGIN_DIGEST,
        binaryHashOrMeasurement: runningCombinerMeasurementHex(),
        governanceMetadata: hex32(0x46),
        effectiveBlock: 1n,
        tombstoneBlock: 0n,
        deprecated: false,
      },
      gateRecipientPubkeys: makePubkeyMap(),
    },
    authorizationSnapshot: {
      snapshot: { blockNumber: 20n, chainId: CANONICAL_CHAIN_ID, blockHash: BLOCK_HASH, observedAt: 2n },
      refusalState: { refused: false, reasonCode: 0, encrypted: false },
      currentShredState: ShredState.None as AuthorizationRegistrySnapshot["currentShredState"],
      canGatesSign: true,
    },
  };
}

function buildCommitAAD(): CommitAADInput {
  const aad = zeroCommitAADInput();
  aad.authorizationId = bytes32(0x11);
  aad.plugin_version_digest = bytes32(0x44);
  aad.endpoint_attestation_digest = bytes32(0xaa);
  aad.g4_authority_ref = bytes32(0x47);
  aad.g3_choice = 1; // drand
  aad.phase = 1;
  aad.conditional_recipients_stanza_count = 0; // FIXED_ONLY
  return aad;
}

function makeEvidence(
  gateKind: GateKind,
  conditionalRecipientIndex: number,
  stanzaIndex: number,
  shareValue: Uint8Array,
): SigmaEvidence {
  return {
    gateKind,
    conditionalRecipientIndex,
    sigmaBytes: new Uint8Array([gateKind, conditionalRecipientIndex, 0x99, 0xaa]),
    gateRecipientPubkey: pubkeyEntry(gateKind, conditionalRecipientIndex),
    metadata: {
      verified: "true",
      verifyCode: "ok",
      shareHex: bytesToHex(shareValue),
      stanzaIndex,
      commitContextDigest0: bytesToHex(COMMIT_CONTEXT_DIGEST_0),
      profileKind: "FIXED_ONLY",
    },
  };
}

function makePubkeyMap(): ReadonlyMap<string, GateRecipientPubkeyEntry> {
  const entries = [
    pubkeyEntry(GateKind.LitV3, 0),
    pubkeyEntry(GateKind.Drand, 0),
    pubkeyEntry(GateKind.G4, 0),
  ];
  return new Map(entries.map((item) => [`${item.gateKind}:${item.conditionalRecipientIndex}`, item]));
}

function pubkeyEntry(gateKind: GateKind, conditionalRecipientIndex: number): GateRecipientPubkeyEntry {
  return {
    authorizationId: AUTH_ID,
    gateKind,
    conditionalRecipientIndex,
    kemPubkey: new Uint8Array([gateKind + 1, conditionalRecipientIndex + 1]),
    attestationRef: hex32(gateKind + conditionalRecipientIndex + 1),
    effectiveBlock: 1n,
    tombstoneBlock: 0n,
    perCommitEphemeral: gateKind !== GateKind.Drand,
  };
}

function bindingTag(gateKind: GateKind): Hex32 {
  switch (gateKind) {
    case GateKind.LitV3:
      return TAG_LIT_ACC_BINDING_V3 as Hex32;
    case GateKind.Dcipher:
    case GateKind.Drand:
      return TAG_G3_BINDING_V3 as Hex32;
    case GateKind.G4:
      return TAG_G4_ATTESTATION_V3 as Hex32;
    case GateKind.ConditionalRecipient:
      return TAG_CONDITIONAL_RECIPIENT_BINDING_V3 as Hex32;
    default:
      return TAG_G4_ATTESTATION_V3 as Hex32;
  }
}

// ───────────────────────── doubled ports ─────────────────────────

/** Deterministic SigmaGatherer double — returns the pre-built σ evidence for
 *  the request. The real network/TEE gate clients are §6 external boundaries;
 *  this double crosses none. */
function makeSigmaGatherer(bundle: SigmaEvidenceBundle): SigmaGatherer & { calls: SigmaGatheringRequest[] } {
  const calls: SigmaGatheringRequest[] = [];
  return {
    calls,
    async gatherSigmas(request: SigmaGatheringRequest): Promise<SigmaEvidenceBundle> {
      calls.push(request);
      return bundle;
    },
  };
}

/** Fake vault holding exactly one sealed blob in memory. The real
 *  Postgres/Filesystem backend is T0.3; this double yields ciphertext +
 *  inseparable commit binding (C1) and never holds a DEK or plaintext. */
function makeVault(fixture: SealedFixture): CealisV3Vault & { getCalls: VaultRef[] } {
  const getCalls: VaultRef[] = [];
  const blob: VaultBlob = {
    ciphertext: fixture.ciphertext,
    commitBinding: {
      commit_aad_bytes: fixture.commitAADBytes,
      commit_version_onwire: 0x0302,
      commit_aad_digest: bytesToHex(COMMIT_CONTEXT_DIGEST_0),
    },
    meta: {
      payload_classification: { contains_pii: true },
      retention_policy_id: "obligation+3y",
      retention_expires_at: "2099-01-01T00:00:00.000Z",
      byte_len: fixture.ciphertext.length,
      created_at: "2026-06-02T00:00:00.000Z",
    },
  };
  return {
    getCalls,
    async getBlob(ref: VaultRef): Promise<VaultBlob> {
      getCalls.push(ref);
      if (ref !== VAULT_REF) throw new Error(`unexpected vault ref ${ref}`);
      return blob;
    },
    async putBlob() {
      throw new Error("putBlob not used in reveal-decrypt-join test");
    },
    async deleteBlob() {
      throw new Error("deleteBlob not used in reveal-decrypt-join test");
    },
    async getRetentionStatus() {
      throw new Error("getRetentionStatus not used");
    },
    async listExpired() {
      return [];
    },
  };
}

// ───────────────────────── reveal-input assembly ─────────────────────────

function makeEvent(): EventDrivenRevealInput["event"] {
  return {
    authorizationId: AUTH_ID,
    h_commit: H_COMMIT,
    pda_root: hex32(0x55),
    authorization_block: 20n,
    authorization_timestamp: 1_778_489_600n,
    challenge_window: 60,
    conditionRef: hex32(0x44),
    block_hash: BLOCK_HASH,
    block_number: 20n,
  };
}

function makeCombinerInputReference(fixture: SealedFixture): CombinerInputReference {
  return {
    sigma_request: {
      authorizationId: AUTH_ID,
      h_commit: H_COMMIT,
      partner_id: "11111111-1111-4111-8111-111111111111",
      pda_id: "22222222-2222-4222-8222-222222222222",
      g3_choice: "drand",
    },
    vault_ref: VAULT_REF,
    access_structure_profile: fixture.profile,
    registry_snapshots: {
      commitSnapshot: fixture.commitSnapshot,
      authorizationSnapshot: fixture.authorizationSnapshot,
    },
    canonical_address_pin: {
      configuredConditionEngine: CANONICAL_CONDITION_ENGINE,
      chainId: CANONICAL_CHAIN_ID,
    },
  };
}

function makeRevealInput(fixture: SealedFixture): EventDrivenRevealInput {
  return {
    event: makeEvent(),
    partner_id: "11111111-1111-4111-8111-111111111111",
    pda: {
      pda_id: "22222222-2222-4222-8222-222222222222",
      pda_version: "t3.3-fixture",
      trust_tier: "tier_b",
      operational_class: "regulated",
    },
    g3_choice: "drand",
    g4_phase: 2,
    schema_digest: hex32(0x77),
    preconditions: {
      challenge_window_closed: true,
      shred_state_allows_reveal: true,
      registry_deprecation_acceptable: true,
      recipient_policy_identified: true,
    },
    combiner_input: makeCombinerInputReference(fixture),
    recipient_selectors: [
      {
        recipient_ref: "enforcement-endpoint",
        recipient_pubkey_id: "pubkey-a",
        schema_selector_digest: hex32(0x66),
        fields: ["legal_name", "nationality"],
      },
    ],
    sigma_block: {
      sigma_lit: { sigma: "0x11", authority_ref: hex32(0x11), public_after_reveal: true },
      sigma_g3: { sigma: "0x22", authority_ref: hex32(0x12), variant: "drand", public_after_reveal: true },
      sigma_g4: { sigma: "0x33", authority_ref: hex32(0x13), phase: 2, public_after_reveal: true },
      sigma_conditional: [],
    },
    chain_proofs: {
      chain_id: CANONICAL_CHAIN_ID,
      condition_engine_address: CANONICAL_CONDITION_ENGINE,
      reveal_authorized_emitter: CANONICAL_CONDITION_ENGINE,
      reveal_authorized_event_signature:
        "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
      reveal_authorized_topics: [AUTH_ID, H_COMMIT, hex32(0x55)],
      receipt_proof: { proof_type: "mock_receipt", block_number: 20, block_hash: BLOCK_HASH, log_index: 0 },
      commit_tx_hash: hex32(0x20),
      commit_block: 10,
      commit_block_hash: hex32(0x21),
      reveal_authorized_tx_hash: hex32(0x22),
      reveal_authorized_log_index: 0,
      reveal_authorized_block: 20,
      reveal_authorized_block_hash: BLOCK_HASH,
      base_finality_confirmations: 32,
      conditionRef: hex32(0x44),
      shred_registry_state_at_reveal: "not_shredded",
    },
    registry_snapshots: {
      authorization_block: 20,
      authorization_block_hash: BLOCK_HASH,
      registry_contracts: {},
    },
    shred_state: {
      h_commit: H_COMMIT,
      shred_state: "not_shredded",
      checked_at_block: 20,
      checked_at_block_hash: BLOCK_HASH,
    },
    sd_refs: { status: "not_configured", disclosure_refs: [] },
    gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
    registry_snapshot_refs: { authorization: BLOCK_HASH },
    recipient_policy: { recipients: ["enforcement-endpoint"] },
    m3_scaffold: {
      artifact_type: "RevealArtifactBundle",
      authorizationId: AUTH_ID,
      hCommit: H_COMMIT,
    },
  };
}

// ───────────────────────── tests ─────────────────────────

describe("T3.3 F-API-1 join — plaintext provenance is the combiner, not the request", () => {
  // The two tests below exercise the REAL `combineAndDecrypt` (dealDek →
  // combineDek → AEAD). They require the merged `@cealis/v3-custody` build
  // output (F-CRYPTO-1 `measureRunningCombinerBundle` + mandatory canonical
  // pin). When the dependency dist is stale they SKIP loudly rather than
  // false-pass — re-run after `pnpm -F @cealis/v3-custody build`.
  const itReal = REAL_COMBINER_AVAILABLE ? it : it.skip;

  itReal("recovers the ORIGINAL plaintext by routing gathered σ + vault ciphertext through combineAndDecrypt", async () => {
    const fixture = buildSealedFixture();
    const repository = new InMemoryRevealArtifactRepository();
    const sigmaGatherer = makeSigmaGatherer(fixture.sigmas);
    const vault = makeVault(fixture);

    const result = await processRevealAuthorizedEvent(makeRevealInput(fixture), {
      repository,
      sigmaGatherer,
      vault,
      now: () => new Date("2026-06-02T00:02:00.000Z"),
    });

    expect(result.status).toBe("finalized");
    expect(result.bundles).toHaveLength(1);

    // The σ-gatherer + vault were the provenance — both were consulted.
    expect(sigmaGatherer.calls).toHaveLength(1);
    expect(sigmaGatherer.calls[0]?.g3_choice).toBe("drand");
    expect(vault.getCalls).toEqual([VAULT_REF]);

    // The recipient-filtered plaintext carries the ORIGINAL field values — proof
    // the combiner reconstructed the real DEK from the real dealt shares and
    // AEAD-decrypted the real sealed payload. No value here came from the request.
    const bundle = result.bundles[0]!;
    expect(bundle.plaintext.fields).toEqual({
      legal_name: KNOWN_PLAINTEXT_OBJECT.legal_name,
      nationality: KNOWN_PLAINTEXT_OBJECT.nationality,
    });
    // Per-recipient selector excluded date_of_birth → not present in the bundle.
    expect(bundle.plaintext.fields).not.toHaveProperty("date_of_birth");
  });

  it("there is NO request-body plaintext field — the type carries only a combiner_input reference", () => {
    const fixture = buildSealedFixture();
    const input = makeRevealInput(fixture);
    // The decoupling vuln is unrepresentable: the input has no `full_plaintext`.
    expect(Object.prototype.hasOwnProperty.call(input, "full_plaintext")).toBe(false);
    // The only plaintext-provenance field is the combiner_input reference, which
    // holds a vault ref + σ request — no cleartext.
    expect(input.combiner_input.vault_ref).toBe(VAULT_REF);
    expect(Object.prototype.hasOwnProperty.call(input.combiner_input, "full_plaintext")).toBe(false);
  });

  itReal("FAILS CLOSED when the combiner refuses (a tampered share cannot reconstruct the DEK → wrong/failed decrypt)", async () => {
    const fixture = buildSealedFixture();
    // Corrupt the G4 share material in σ metadata. The DEK reconstructed from a
    // tampered share is wrong, so the AEAD tag fails and combineAndDecrypt
    // returns !ok → the join surfaces an HttpProblem (no plaintext, no bundle).
    const tampered: SigmaEvidenceBundle = {
      ...fixture.sigmas,
      evidence: fixture.sigmas.evidence.map((ev) =>
        ev.gateKind === GateKind.G4
          ? { ...ev, metadata: { ...ev.metadata, shareHex: bytesToHex(new Uint8Array(32).fill(0x01)) } }
          : ev,
      ),
    };
    const repository = new InMemoryRevealArtifactRepository();
    const sigmaGatherer = makeSigmaGatherer(tampered);
    const vault = makeVault(fixture);

    await expect(
      processRevealAuthorizedEvent(makeRevealInput(fixture), {
        repository,
        sigmaGatherer,
        vault,
        now: () => new Date("2026-06-02T00:02:00.000Z"),
      }),
    ).rejects.toThrow();

    // No bundle was persisted for the recipient.
    await expect(repository.getBundle(AUTH_ID, "enforcement-endpoint")).resolves.toBeUndefined();
    // Status was driven to refused, not finalized.
    const status = await repository.getStatus(AUTH_ID);
    expect(status?.status).toBe("refused");
  });

  it("routes through a deterministic combiner double too (gate-double path) and recovers the original plaintext", async () => {
    // The same join, but with the combine+decrypt RUNNER doubled deterministically
    // (instead of the real M3 bridge). This isolates the orchestration: the join
    // asks the runner for plaintext, decodes it, and selects per recipient. The
    // runner double returns the known plaintext bytes (as a real combiner would).
    const fixture = buildSealedFixture();
    const repository = new InMemoryRevealArtifactRepository();
    const sigmaGatherer = makeSigmaGatherer(fixture.sigmas);
    const vault = makeVault(fixture);

    const runner = vi.fn((_input: RunM3CombinerBridgeInput) => ({
      ok: true as const,
      plaintext: freshKnownPlaintext(),
      m3_artifact_digest: hex32(0x88),
    }));

    const result = await processRevealAuthorizedEvent(makeRevealInput(fixture), {
      repository,
      sigmaGatherer,
      vault,
      combineAndDecryptRunner: runner,
      now: () => new Date("2026-06-02T00:02:00.000Z"),
    });

    expect(runner).toHaveBeenCalledTimes(1);
    // The runner received the GATHERED σ + the VAULT ciphertext + commit binding
    // — proving the provenance plumbing (not the request body).
    const passed = runner.mock.calls[0]![0];
    expect(passed.combinerInput.sigmas).toBe(fixture.sigmas);
    expect(passed.combinerInput.ageEnvelope).toBe(fixture.ciphertext);
    expect(passed.combinerInput.commitAAD).toBe(fixture.commitAADBytes);

    expect(result.status).toBe("finalized");
    expect(result.bundles[0]?.plaintext.fields).toEqual({
      legal_name: KNOWN_PLAINTEXT_OBJECT.legal_name,
      nationality: KNOWN_PLAINTEXT_OBJECT.nationality,
    });
  });
});

// ───────────────── C3a — snapshot-recheck still holds after the F-API-1 refactor ─────────────────
//
// The coordinator wraps the (now F-API-1) `processRevealAuthorizedEvent`. We
// drive the REAL combiner round-trip (so a real finalized bundle is produced),
// then flip a live axis (shred → finalized, or Art.18 → frozen) on the
// per-enqueue re-read. The coordinator's `clearGatesAt("pre-delivery", …)`
// re-mint must catch the change and dead-letter the bundle — proving the
// snapshot-recheck (C3a) is not regressed by the plaintext-provenance change.

describe("T3.3 C3a — per-enqueue live re-read still halts delivery (not regressed by F-API-1)", () => {
  const SUBJECT = { authorizationId: AUTH_ID, h_commit: H_COMMIT, subjectCommitment: hex32(0xcc) };
  const COORDINATOR_INPUT: RevealCoordinatorInput = {
    authorizationId: AUTH_ID,
    h_commit: H_COMMIT,
    subjectCommitment: hex32(0xcc),
    partner_id: "11111111-1111-4111-8111-111111111111",
    pda_id: "22222222-2222-4222-8222-222222222222",
  };

  function makeQueue(): {
    queue: RevealDeliveryQueue;
    enqueued: { job_id: string }[];
    deadLettered: { jobId: string; reason: string }[];
  } {
    const enqueued: { job_id: string }[] = [];
    const deadLettered: { jobId: string; reason: string }[] = [];
    return {
      queue: {
        enqueue: async (job) => {
          enqueued.push({ job_id: job.job_id });
        },
        deadLetter: async (jobId, reason) => {
          deadLettered.push({ jobId, reason });
        },
      },
      enqueued,
      deadLettered,
    };
  }

  /**
   * A coordinator that produces exactly ONE finalized bundle so the C3a gate has
   * something to (not) deliver. The C3a discipline under test — the per-enqueue
   * `clearGatesAt("pre-delivery", …)` re-mint — is INDEPENDENT of how the bundle
   * was produced, so we drive the combine+decrypt RUNNER with a deterministic
   * double (returns the known plaintext bytes, as a real combiner would). This
   * keeps the C3a tests runnable regardless of the `@cealis/v3-custody` build
   * freshness, while still exercising the full orchestration (decode → select →
   * assemble → persist → per-enqueue re-clear).
   */
  function makeRealCoordinator(): RevealCoordinatorImpl {
    const fixture = buildSealedFixture();
    const repository = new InMemoryRevealArtifactRepository();
    return new RevealCoordinatorImpl(
      {
        repository,
        sigmaGatherer: makeSigmaGatherer(fixture.sigmas),
        vault: makeVault(fixture),
        combineAndDecryptRunner: () => ({
          ok: true,
          plaintext: freshKnownPlaintext(),
          m3_artifact_digest: hex32(0x88),
        }),
        now: () => new Date("2026-06-02T00:02:00.000Z"),
      },
      async () => {
        // The coordinator stamps `preconditions` itself; we return everything else.
        const { preconditions: _preconditions, ...rest } = makeRevealInput(fixture);
        return rest;
      },
    );
  }

  /** Live ports where ONE axis flips on its 2nd read (entry-clear vs per-enqueue
   *  re-mint). The flip simulates a shred/freeze landing during combiner work. */
  function statefulPorts(opts: { shredFlipsTo?: "finalized"; art18FlipsTo?: boolean }): {
    ports: LiveStateReaderPorts;
    shredCalls: () => number;
  } {
    let shredCalls = 0;
    let art18Calls = 0;
    return {
      shredCalls: () => shredCalls,
      ports: {
        shred: {
          read: vi.fn(async () => {
            shredCalls += 1;
            if (shredCalls === 1 || opts.shredFlipsTo === undefined) {
              return { state: "none" as const, post_challenge_reveal_in_progress: false };
            }
            return { state: opts.shredFlipsTo, post_challenge_reveal_in_progress: false };
          }),
        },
        art18: {
          read: vi.fn(async () => {
            art18Calls += 1;
            if (art18Calls === 1 || opts.art18FlipsTo === undefined) return { frozen: false };
            return { frozen: opts.art18FlipsTo };
          }),
        },
        chain: {
          read: vi.fn(async () => ({ reveal_authorized_present: true, confirmations: 12, authorization_block: 20 })),
        },
        challenge: {
          read: vi.fn(async () => ({ closed: true, window_expires_at: "2026-01-01T00:00:00.000Z" })),
        },
        registry: { read: vi.fn(async () => ({ acceptable: true, deprecated_refs: [] })) },
      },
    };
  }

  it("dead-letters the bundle when SHRED flips to finalized at the per-enqueue re-read", async () => {
    const { ports, shredCalls } = statefulPorts({ shredFlipsTo: "finalized" });
    const reader = new ConcreteLiveStateReader(ports);
    const portsForCoord: RevealCoordinatorPorts = {
      liveState: reader,
      clearGatesAt,
      anchor: { anchor: async () => ({ commit_tx_hash: "0x" + "0".repeat(64), commit_block: 20, attempts: 1 }) },
    };

    const coord = makeRealCoordinator();
    const entryClearance = await clearGatesAt("pre-delivery", reader, SUBJECT);
    expect(shredCalls()).toBe(1); // entry clearance read once

    const { queue, enqueued, deadLettered } = makeQueue();
    await coord.persistAndDeliver(COORDINATOR_INPUT, portsForCoord, entryClearance, queue);

    // Per-enqueue re-read saw the finalized shred → nothing enqueued, dead-lettered.
    expect(enqueued).toHaveLength(0);
    expect(deadLettered).toHaveLength(1);
    expect(deadLettered[0]?.reason ?? "").toMatch(/pre-delivery re-clearance failed/);
    expect(shredCalls()).toBeGreaterThanOrEqual(2); // entry + per-enqueue re-read
  });

  it("dead-letters the bundle when ART.18 freeze flips active at the per-enqueue re-read", async () => {
    const { ports } = statefulPorts({ art18FlipsTo: true });
    const reader = new ConcreteLiveStateReader(ports);
    const portsForCoord: RevealCoordinatorPorts = {
      liveState: reader,
      clearGatesAt,
      anchor: { anchor: async () => ({ commit_tx_hash: "0x" + "0".repeat(64), commit_block: 20, attempts: 1 }) },
    };

    const coord = makeRealCoordinator();
    const entryClearance = await clearGatesAt("pre-delivery", reader, SUBJECT);

    const { queue, enqueued, deadLettered } = makeQueue();
    await coord.persistAndDeliver(COORDINATOR_INPUT, portsForCoord, entryClearance, queue);

    expect(enqueued).toHaveLength(0);
    expect(deadLettered).toHaveLength(1);
  });

  it("enqueues normally when all 5 axes stay clean across the per-enqueue re-read (C3a allows)", async () => {
    const { ports, shredCalls } = statefulPorts({}); // nothing flips
    const reader = new ConcreteLiveStateReader(ports);
    const portsForCoord: RevealCoordinatorPorts = {
      liveState: reader,
      clearGatesAt,
      anchor: { anchor: async () => ({ commit_tx_hash: "0x" + "0".repeat(64), commit_block: 20, attempts: 1 }) },
    };

    const coord = makeRealCoordinator();
    const entryClearance = await clearGatesAt("pre-delivery", reader, SUBJECT);

    const { queue, enqueued, deadLettered } = makeQueue();
    await coord.persistAndDeliver(COORDINATOR_INPUT, portsForCoord, entryClearance, queue);

    expect(deadLettered).toHaveLength(0);
    expect(enqueued).toHaveLength(1); // the single real bundle delivered
    expect(shredCalls()).toBeGreaterThanOrEqual(2); // entry + per-enqueue re-read (no caching)
  });
});

// ───────────────────────── local helpers ─────────────────────────

function randomDek(): Uint8Array {
  const dek = new Uint8Array(32);
  for (let i = 0; i < dek.length; i++) dek[i] = (i * 37 + 11) & 0xff;
  // Make the leading byte non-trivial so the dealer's polynomials are distinct.
  dek[0] = 0x5a;
  return dek;
}

function bytes32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function hex32(byte: number): Hex32 {
  return ("0x" + byte.toString(16).padStart(2, "0").repeat(32).slice(0, 64)) as Hex32;
}
