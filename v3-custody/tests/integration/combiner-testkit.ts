import {
  encodeAgeEnvelope,
  encodeCommitAAD,
  encryptPayload,
  TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
  TAG_G3_BINDING_V3,
  TAG_G4_ATTESTATION_V3,
  TAG_LIT_ACC_BINDING_V3,
  zeroCommitAADInput,
  type CommitAADInput,
  type Hex32,
} from "@cealis/v3-crypto";
import type { CombineAndDecryptInput } from "../../src/combiner/index.js";
import {
  GateKind,
  ShredState,
  type AccessStructureProfile,
  type GateRecipientPubkeyEntry,
  type SigmaEvidence,
} from "../../src/index.js";
import { bytesToHex } from "../../src/combiner/jcs-canonicalize.js";
import { measureRunningCombinerBundle } from "../../src/combiner/plugin-integrity.js";
import { computeConditionalRecipientsPolicyDigest } from "../../src/access-structure/policy-digest.js";

export const AUTH_ID = hex32(0x11);
export const H_COMMIT = hex32(0x22);
export const BLOCK_HASH = hex32(0x33);
export const PLUGIN_DIGEST = hex32(0x44);
// F-CRYPTO-1 (security-audit-2026-06-02): the combiner now MEASURES its own
// running code (`measureRunningCombinerBundle`) and binds that measurement to
// the `PluginHashRegistry` entry's `binaryHashOrMeasurement`, instead of the
// old self-comparing tautology. For the happy-path fixtures to pass a REAL
// attestation (not a no-op), the fixture registry entry must carry the actual
// measured digest of the running combiner bundle — exactly what a deployment's
// build pipeline stamps on-chain. Tests that want a mismatch override the env
// (`CEALIS_COMBINER_BINARY_HASH`, see combiner-stale-plugin-hash.test.ts).
export const PLUGIN_BINARY_HASH = bytesToHex(measureRunningCombinerBundle()) as Hex32;
export const COMMIT_CONTEXT_DIGEST_0 = bytes32(0xaa);
export const DEK = bytes32(0x5a);
export const PLAINTEXT = new TextEncoder().encode("cealis combiner plaintext");

export interface FixtureOptions {
  readonly profile?: AccessStructureProfile;
  readonly phase?: 1 | 2;
  readonly g3Choice?: 0 | 1;
  readonly evidence?: readonly SigmaEvidence[];
  readonly mutateAgeEnvelope?: (bytes: Uint8Array) => Uint8Array;
  readonly mutateCommitAAD?: (aad: CommitAADInput) => CommitAADInput;
  readonly pluginTombstoneBlock?: bigint;
  readonly shredState?: number;
  readonly canGatesSign?: boolean;
  readonly litVendorFamily?: string;
  readonly g4VendorFamily?: string;
  readonly mode3?: boolean;
}

export function makeFixture(options: FixtureOptions = {}): CombineAndDecryptInput {
  const profile = options.profile ?? { kind: "FIXED_ONLY" };
  const commitAAD = makeCommitAAD(profile, options);
  const encrypted = encryptPayload({
    dek: DEK,
    commit_context_digest_0: COMMIT_CONTEXT_DIGEST_0,
    commit_AAD_v0: commitAAD,
    plaintext: PLAINTEXT,
  });
  const defaultEvidence = makeEvidence(profile, commitAAD, options);
  const evidence = options.evidence ?? defaultEvidence;
  const ageEnvelope = encodeAgeEnvelope({
    stanzas: evidence.map((item, index) => ({
      stanza_index: index,
      binding_tag:
        item.gateKind === GateKind.ConditionalRecipient
          ? TAG_CONDITIONAL_RECIPIENT_BINDING_V3
          : bindingTag(item.gateKind),
      plugin_version_digest: commitAAD.plugin_version_digest,
      ciphertext_payload_bytes:
        item.gateKind === GateKind.ConditionalRecipient
          ? new Uint8Array([options.mode3 === true ? 0x03 : 0x01, item.conditionalRecipientIndex])
          : new Uint8Array([item.gateKind, item.conditionalRecipientIndex]),
    })),
    payload_ciphertext: encrypted.ciphertext,
  });
  const finalEnvelope = options.mutateAgeEnvelope?.(ageEnvelope) ?? ageEnvelope;
  return {
    authorizationId: AUTH_ID,
    hCommit: H_COMMIT,
    authorizationBlock: 20n,
    blockHash: BLOCK_HASH,
    commitAAD: encodeCommitAAD(commitAAD),
    ageEnvelope: finalEnvelope,
    // TS-CRYPTO-F-08 (R2b-3 closure, 2026-05-20): canonical-address pin is
    // now MANDATORY on `CombineAndDecryptInput`. Default the testkit fixture
    // to the canonical Base Sepolia entry from
    // `v3-custody/src/chain/canonical-addresses.ts` — every test
    // inherits a clean pin unless it explicitly overrides to exercise a
    // mismatch path (see `combiner-canonicaladdresspin-mandatory.test.ts`).
    canonicalAddressPin: {
      configuredConditionEngine: "0xb09a8300423CA3BD0E028bAB6A6245A248520D02",
      chainId: 84_532,
    },
    // B2 closure "k_conditional from commitAAD not σ-metadata" (R2b-3,
    // 2026-05-20): RECIPIENT_K_OF_N profiles ship the policy alongside
    // the AAD-anchored digest computed inside `makeCommitAAD`. FIXED_ONLY
    // / RECIPIENT_1_OF_1 fixtures omit the field (typed-discriminated
    // absent). Tests that want to exercise the mismatch surface pass an
    // explicit override at the call site (see
    // `combiner-kconditional-from-commitaad.test.ts`).
    ...(profile.kind === "RECIPIENT_K_OF_N"
      ? {
          conditionalRecipientsPolicy: {
            n_conditional: profile.n_conditional,
            k_conditional: profile.k_conditional,
          },
        }
      : {}),
    sigmas: {
      authorizationId: AUTH_ID,
      hCommit: H_COMMIT,
      authorizationBlock: 20n,
      commitBlock: 10n,
      evidence,
    },
    registrySnapshots: {
      commitSnapshot: {
        snapshot: {
          blockNumber: 10n,
          chainId: 84532,
          blockHash: hex32(0x10),
          observedAt: 1n,
        },
        plugin: {
          pluginVersionDigest: PLUGIN_DIGEST,
          binaryHashOrMeasurement: PLUGIN_BINARY_HASH,
          governanceMetadata: hex32(0x46),
          effectiveBlock: 1n,
          tombstoneBlock: options.pluginTombstoneBlock ?? 0n,
          deprecated: false,
        },
        gateRecipientPubkeys: makePubkeyMap(profile, commitAAD.g3_choice),
      },
      authorizationSnapshot: {
        snapshot: {
          blockNumber: 20n,
          chainId: 84532,
          blockHash: BLOCK_HASH,
          observedAt: 2n,
        },
        refusalState: { refused: false, reasonCode: 0, encrypted: false },
        currentShredState: (options.shredState ?? ShredState.None) as 0 | 1 | 2 | 3 | 4 | 5 | 6,
        canGatesSign: options.canGatesSign ?? true,
      },
    },
  };
}

export function makeEvidence(
  profile: AccessStructureProfile,
  commitAAD: CommitAADInput,
  options: FixtureOptions = {},
): readonly SigmaEvidence[] {
  const g3Kind = commitAAD.g3_choice === 0 ? GateKind.Dcipher : GateKind.Drand;
  const base = [
    sigma(GateKind.LitV3, 0, 0, profile, options),
    sigma(g3Kind, 0, 1, profile, options),
    sigma(GateKind.G4, 0, 2, profile, options),
  ];
  if (profile.kind === "RECIPIENT_1_OF_1") {
    base.push(sigma(GateKind.ConditionalRecipient, 0, 3, profile, options));
  }
  if (profile.kind === "RECIPIENT_K_OF_N") {
    for (let i = 0; i < profile.k_conditional; i++) {
      base.push(sigma(GateKind.ConditionalRecipient, i, 3 + i, profile, options));
    }
  }
  return base;
}

export function profile1of1(): AccessStructureProfile {
  return { kind: "RECIPIENT_1_OF_1" };
}

export function profileKofN(): AccessStructureProfile {
  return { kind: "RECIPIENT_K_OF_N", n_conditional: 5, k_conditional: 2 };
}

export function hex32(byte: number): Hex32 {
  return bytesToHex(bytes32(byte)) as Hex32;
}

export function bytes32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function makeCommitAAD(profile: AccessStructureProfile, options: FixtureOptions): CommitAADInput {
  const aad = zeroCommitAADInput();
  aad.authorizationId = bytes32(0x11);
  aad.plugin_version_digest = bytes32(0x44);
  aad.endpoint_attestation_digest = bytes32(0xaa);
  aad.g4_authority_ref = bytes32(0x47);
  aad.g3_choice = options.g3Choice ?? 1;
  aad.phase = options.phase ?? 1;
  aad.conditional_recipients_stanza_count =
    profile.kind === "FIXED_ONLY" ? 0 : profile.kind === "RECIPIENT_1_OF_1" ? 1 : profile.n_conditional;
  // B2 closure "k_conditional from commitAAD not σ-metadata" (R2b-3,
  // 2026-05-20): populate the on-chain-anchored digest for RECIPIENT_K_OF_N
  // fixtures so the combiner's pipeline-internal digest verification
  // passes. FIXED_ONLY / RECIPIENT_1_OF_1 keep the zero-bytes default from
  // `zeroCommitAADInput()` (no policy, no digest).
  if (profile.kind === "RECIPIENT_K_OF_N") {
    aad.conditional_recipients_policy_digest = computeConditionalRecipientsPolicyDigest({
      n_conditional: profile.n_conditional,
      k_conditional: profile.k_conditional,
    });
  }
  return options.mutateCommitAAD?.(aad) ?? aad;
}

function makePubkeyMap(profile: AccessStructureProfile, g3Choice: number): ReadonlyMap<string, GateRecipientPubkeyEntry> {
  const g3Kind = g3Choice === 0 ? GateKind.Dcipher : GateKind.Drand;
  const entries = [
    entry(GateKind.LitV3, 0),
    entry(g3Kind, 0),
    entry(GateKind.G4, 0),
  ];
  if (profile.kind === "RECIPIENT_1_OF_1") entries.push(entry(GateKind.ConditionalRecipient, 0));
  if (profile.kind === "RECIPIENT_K_OF_N") {
    for (let i = 0; i < profile.n_conditional; i++) entries.push(entry(GateKind.ConditionalRecipient, i));
  }
  return new Map(entries.map((item) => [`${item.gateKind}:${item.conditionalRecipientIndex}`, item]));
}

function sigma(
  gateKind: GateKind,
  conditionalRecipientIndex: number,
  stanzaIndex: number,
  profile: AccessStructureProfile,
  options: FixtureOptions,
): SigmaEvidence {
  const metadata: Record<string, string | number | bigint | Hex32> = {
    verified: "true",
    shareHex: bytesToHex(DEK),
    stanzaIndex,
    commitContextDigest0: bytesToHex(COMMIT_CONTEXT_DIGEST_0),
    profileKind: profile.kind,
  };
  if (profile.kind === "RECIPIENT_K_OF_N") {
    metadata.nConditional = profile.n_conditional;
    metadata.kConditional = profile.k_conditional;
  }
  if (options.litVendorFamily !== undefined) metadata.litVendorFamily = options.litVendorFamily;
  if (options.g4VendorFamily !== undefined) metadata.g4VendorFamily = options.g4VendorFamily;
  return {
    gateKind,
    conditionalRecipientIndex,
    sigmaBytes: new Uint8Array([gateKind, conditionalRecipientIndex, 0x99, 0xaa]),
    gateRecipientPubkey: entry(gateKind, conditionalRecipientIndex),
    metadata,
  };
}

function entry(gateKind: GateKind, conditionalRecipientIndex: number): GateRecipientPubkeyEntry {
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
      return TAG_LIT_ACC_BINDING_V3;
    case GateKind.Dcipher:
    case GateKind.Drand:
      return TAG_G3_BINDING_V3;
    case GateKind.G4:
      return TAG_G4_ATTESTATION_V3;
    case GateKind.ConditionalRecipient:
      return TAG_CONDITIONAL_RECIPIENT_BINDING_V3;
  }
}
