// reveal-combiner-testkit — shared doubles for the F-API-1 reveal-decrypt join.
//
// WHY THIS EXISTS
// ---------------
// Wave-3 F-API-1 rewrote `processRevealAuthorizedEvent` so the reveal path no
// longer accepts cleartext from the request body. The old `full_plaintext`
// field is gone; instead the input carries a `combiner_input` REFERENCE
// (σ-gathering request + opaque vault ref + access-structure profile + registry
// snapshots + canonical-address pin), and the plaintext is PRODUCED by routing
// gathered σ + vault ciphertext through the cryptographic combiner.
//
// Most integration tests assert ORCHESTRATION behaviour (recipient selection,
// refusal codes, Art.18 defer, archetype coverage, multi-recipient fan-out, the
// shred-cascade block) — NOT the byte-level crypto round-trip (that is owned by
// `tests/combiner-orchestrator/reveal-decrypt-join.test.ts`). For those tests the
// honest, build-freshness-independent double is the combiner RUNNER double: the
// combine+decrypt step is replaced by a deterministic stand-in that returns the
// KNOWN plaintext bytes (exactly as a real combiner would after reconstructing
// the DEK and AEAD-decrypting). The σ-gatherer + vault are also doubled (the real
// ones are §6 vendor / T0.3 backend boundaries). This preserves each test's
// behavioural assertions while only changing HOW the plaintext enters the path
// (now via the combiner reference + injected doubles, not the request body).
//
// The doubles cross NO vendor boundary and hold NO real key material.

import { vi } from "vitest";

import type {
  AccessStructureProfile,
  AuthorizationRegistrySnapshot,
  CommitRegistrySnapshot,
  GateRecipientPubkeyEntry,
  SigmaEvidence,
  SigmaEvidenceBundle,
} from "../../src/m3-imports.js";
import { GateKind, ShredState } from "../../src/m3-imports.js";
import type {
  CombinerInputReference,
  CombineAndDecryptRunner,
} from "../../src/combiner-orchestrator/index.js";
import type { RunM3CombinerBridgeInput } from "../../src/combiner-orchestrator/m3-bridge.js";
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

/** Canonical pin matching the live Base-Sepolia ConditionEngine (testnet-only; deployed bytecode may drift from source — see deployments/README.md). */
const CANONICAL_CONDITION_ENGINE = "0xb09a8300423CA3BD0E028bAB6A6245A248520D02" as const;
const CANONICAL_CHAIN_ID = 84_532;

function hex32(byte: number): Hex32 {
  return ("0x" + byte.toString(16).padStart(2, "0").repeat(32).slice(0, 64)) as Hex32;
}

function pubkeyEntry(authId: Hex32, gateKind: GateKind, conditionalRecipientIndex: number): GateRecipientPubkeyEntry {
  return {
    authorizationId: authId,
    gateKind,
    conditionalRecipientIndex,
    kemPubkey: new Uint8Array([gateKind + 1, conditionalRecipientIndex + 1]),
    attestationRef: hex32(gateKind + conditionalRecipientIndex + 1),
    effectiveBlock: 1n,
    tombstoneBlock: 0n,
    perCommitEphemeral: gateKind !== GateKind.Drand,
  };
}

function makeEvidence(authId: Hex32, gateKind: GateKind, stanzaIndex: number): SigmaEvidence {
  return {
    gateKind,
    conditionalRecipientIndex: 0,
    sigmaBytes: new Uint8Array([gateKind, 0, 0x99, 0xaa]),
    gateRecipientPubkey: pubkeyEntry(authId, gateKind, 0),
    metadata: {
      verified: "true",
      verifyCode: "ok",
      // No real share material: the combine+decrypt RUNNER is doubled in this
      // testkit, so the real `combineDek` Lagrange reconstruct never runs. The
      // byte-exact share path is exercised in reveal-decrypt-join.test.ts.
      shareHex: "0x" + "00".repeat(32),
      stanzaIndex,
      profileKind: "FIXED_ONLY",
    },
  };
}

/** A FIXED_ONLY σ evidence bundle over {Lit, G3(drand), G4}. */
function makeSigmaBundle(authId: Hex32, hCommit: Hex32): SigmaEvidenceBundle {
  return {
    authorizationId: authId,
    hCommit,
    authorizationBlock: 20n,
    commitBlock: 10n,
    evidence: [
      makeEvidence(authId, GateKind.LitV3, 0),
      makeEvidence(authId, GateKind.Drand, 1),
      makeEvidence(authId, GateKind.G4, 2),
    ],
  };
}

function makeCommitSnapshot(): CommitRegistrySnapshot {
  return {
    snapshot: { blockNumber: 10n, chainId: CANONICAL_CHAIN_ID, blockHash: hex32(0x10), observedAt: 1n },
    plugin: {
      pluginVersionDigest: hex32(0x44),
      binaryHashOrMeasurement: hex32(0x45),
      governanceMetadata: hex32(0x46),
      effectiveBlock: 1n,
      tombstoneBlock: 0n,
      deprecated: false,
    },
    gateRecipientPubkeys: new Map(),
  };
}

function makeAuthorizationSnapshot(blockHash: Hex32): AuthorizationRegistrySnapshot {
  return {
    snapshot: { blockNumber: 20n, chainId: CANONICAL_CHAIN_ID, blockHash, observedAt: 2n },
    refusalState: { refused: false, reasonCode: 0, encrypted: false },
    currentShredState: ShredState.None as AuthorizationRegistrySnapshot["currentShredState"],
    canGatesSign: true,
  };
}

export interface RevealCombinerDoubles {
  /** The `combiner_input` reference to put on `EventDrivenRevealInput`. */
  readonly combinerInput: CombinerInputReference;
  /** Injected σ-gatherer double (records calls). */
  readonly sigmaGatherer: SigmaGatherer & { calls: SigmaGatheringRequest[] };
  /** Injected vault double (records getBlob refs). */
  readonly vault: CealisV3Vault & { getCalls: VaultRef[] };
  /** Injected combine+decrypt runner double returning the known plaintext. */
  readonly combineAndDecryptRunner: CombineAndDecryptRunner;
  /** The vault ref the combiner_input points at. */
  readonly vaultRef: VaultRef;
}

/**
 * Build the `combiner_input` reference + the three injected doubles
 * (sigmaGatherer, vault, combineAndDecryptRunner) for a known plaintext object.
 * The runner double returns `JSON.stringify(plaintext)` as UTF-8 bytes — exactly
 * what the JSON/UTF-8 plaintext decoder consumes — so per-recipient selection
 * behaves identically to the old `full_plaintext` path.
 *
 * @param plaintext    the known plaintext object (the bytes the combiner "recovers")
 * @param opts.authId  authorization id (defaults to hex32(0x11))
 * @param opts.hCommit h_commit (defaults to hex32(0x22))
 * @param opts.blockHash authorization block hash (defaults to hex32(0x33))
 * @param opts.g3_choice PDA-selected G3 gate (defaults to "drand")
 * @param opts.partner_id / opts.pda_id ids threaded into the σ request
 */
export function makeRevealCombinerDoubles(
  plaintext: Readonly<Record<string, unknown>>,
  opts: {
    readonly authId?: Hex32;
    readonly hCommit?: Hex32;
    readonly blockHash?: Hex32;
    readonly g3_choice?: "dcipher" | "drand";
    readonly partner_id?: string;
    readonly pda_id?: string;
    readonly vaultRef?: VaultRef;
  } = {},
): RevealCombinerDoubles {
  const authId = opts.authId ?? hex32(0x11);
  const hCommit = opts.hCommit ?? hex32(0x22);
  const blockHash = opts.blockHash ?? hex32(0x33);
  const g3_choice = opts.g3_choice ?? "drand";
  const partner_id = opts.partner_id ?? "11111111-1111-4111-8111-111111111111";
  const pda_id = opts.pda_id ?? "22222222-2222-4222-8222-222222222222";
  const vaultRef = opts.vaultRef ?? `vault://test/${authId}`;

  const sigmas = makeSigmaBundle(authId, hCommit);
  // The age-envelope ciphertext + commit binding the vault yields. Opaque bytes:
  // the runner is doubled, so the real AEAD decrypt of these bytes never runs.
  const ciphertext = new Uint8Array([0xab, 0xcd, 0xef]);
  const commitAADBytes = new Uint8Array([0x01, 0x02, 0x03]);

  const sigmaCalls: SigmaGatheringRequest[] = [];
  const sigmaGatherer: SigmaGatherer & { calls: SigmaGatheringRequest[] } = {
    calls: sigmaCalls,
    async gatherSigmas(request: SigmaGatheringRequest): Promise<SigmaEvidenceBundle> {
      sigmaCalls.push(request);
      return sigmas;
    },
  };

  const getCalls: VaultRef[] = [];
  const blob: VaultBlob = {
    ciphertext,
    commitBinding: {
      commit_aad_bytes: commitAADBytes,
      commit_version_onwire: 0x0302,
      commit_aad_digest: hex32(0xaa),
    },
    meta: {
      payload_classification: { contains_pii: true },
      retention_policy_id: "obligation+3y",
      retention_expires_at: "2099-01-01T00:00:00.000Z",
      byte_len: ciphertext.length,
      created_at: "2026-06-02T00:00:00.000Z",
    },
  };
  const vault: CealisV3Vault & { getCalls: VaultRef[] } = {
    getCalls,
    async getBlob(ref: VaultRef): Promise<VaultBlob> {
      getCalls.push(ref);
      if (ref !== vaultRef) throw new Error(`unexpected vault ref ${ref}`);
      return blob;
    },
    async putBlob() {
      throw new Error("putBlob not used in reveal-combiner testkit");
    },
    async deleteBlob() {
      throw new Error("deleteBlob not used in reveal-combiner testkit");
    },
    async getRetentionStatus() {
      throw new Error("getRetentionStatus not used in reveal-combiner testkit");
    },
    async listExpired() {
      return [];
    },
  };

  // The combine+decrypt RUNNER double — returns the known plaintext bytes, as a
  // real combiner would after reconstructing the DEK and AEAD-decrypting. Routed
  // the GATHERED σ + the VAULT ciphertext + commit binding (proving the
  // provenance plumbing, not a request body).
  const combineAndDecryptRunner = vi.fn((_input: RunM3CombinerBridgeInput) => ({
    ok: true as const,
    plaintext: new TextEncoder().encode(JSON.stringify(plaintext)),
    m3_artifact_digest: hex32(0x88),
  }));

  const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
  const combinerInput: CombinerInputReference = {
    sigma_request: { authorizationId: authId, h_commit: hCommit, partner_id, pda_id, g3_choice },
    vault_ref: vaultRef,
    access_structure_profile: profile,
    registry_snapshots: {
      commitSnapshot: makeCommitSnapshot(),
      authorizationSnapshot: makeAuthorizationSnapshot(blockHash),
    },
    canonical_address_pin: {
      configuredConditionEngine: CANONICAL_CONDITION_ENGINE,
      chainId: CANONICAL_CHAIN_ID,
    },
  };

  return { combinerInput, sigmaGatherer, vault, combineAndDecryptRunner, vaultRef };
}
