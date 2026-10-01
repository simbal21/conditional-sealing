import { keccak_256 } from "@noble/hashes/sha3";
import type { Hex32 } from "../m1-imports.js";
import type {
  AccessStructureProfile,
  AuthorizationRegistrySnapshot,
  CommitRegistrySnapshot,
} from "../types/index.js";
import type { AdmittedSigmaEvidence } from "./sigma-orchestrator.js";
import {
  asHex32,
  bytesToHex32,
  jcsDigest,
  type JcsValue,
} from "./jcs-canonicalize.js";

export interface RevealArtifactBundle {
  readonly artifact_type: "RevealArtifactBundle";
  readonly artifact_version: 1;
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly authorizationBlock: string;
  readonly blockHash: Hex32;
  readonly profile: JcsValue;
  readonly gateEvidence: readonly JcsValue[];
  readonly plaintextDigest: Hex32;
  readonly registrySnapshotDigests: {
    readonly commitSnapshot: Hex32;
    readonly authorizationSnapshot: Hex32;
  };
}

export function assembleRevealArtifactBundle(input: {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly authorizationBlock: bigint;
  readonly blockHash: Hex32;
  readonly profile: AccessStructureProfile;
  readonly sigmaEvidence: readonly AdmittedSigmaEvidence[];
  readonly plaintext: Uint8Array;
  readonly commitSnapshot: CommitRegistrySnapshot;
  readonly authorizationSnapshot: AuthorizationRegistrySnapshot;
}): { readonly bundle: RevealArtifactBundle; readonly digest: Hex32 } {
  const bundle: RevealArtifactBundle = {
    artifact_type: "RevealArtifactBundle",
    artifact_version: 1,
    authorizationId: input.authorizationId,
    hCommit: input.hCommit,
    authorizationBlock: input.authorizationBlock.toString(),
    blockHash: input.blockHash,
    profile: profileToJcs(input.profile),
    gateEvidence: input.sigmaEvidence.map((evidence) => ({
      gate: evidence.gate,
      conditionalRecipientIndex: evidence.conditionalRecipientIndex,
      sigmaDigest: evidence.sigmaDigest,
      stanzaIndex: evidence.stanzaIndex,
      shareAdmitted: true,
    })),
    plaintextDigest: bytesToHex32(keccak_256(input.plaintext)),
    registrySnapshotDigests: {
      commitSnapshot: digestSnapshot({
        blockNumber: input.commitSnapshot.snapshot.blockNumber.toString(),
        chainId: input.commitSnapshot.snapshot.chainId,
        blockHash: input.commitSnapshot.snapshot.blockHash,
        pluginVersionDigest: input.commitSnapshot.plugin.pluginVersionDigest,
      }),
      authorizationSnapshot: digestSnapshot({
        blockNumber: input.authorizationSnapshot.snapshot.blockNumber.toString(),
        chainId: input.authorizationSnapshot.snapshot.chainId,
        blockHash: input.authorizationSnapshot.snapshot.blockHash,
        canGatesSign: input.authorizationSnapshot.canGatesSign,
        shredState: input.authorizationSnapshot.currentShredState,
        refused: input.authorizationSnapshot.refusalState.refused,
      }),
    },
  };
  return {
    bundle,
    digest: jcsDigest(bundleToJcs(bundle)),
  };
}

function bundleToJcs(bundle: RevealArtifactBundle): JcsValue {
  return {
    artifact_type: bundle.artifact_type,
    artifact_version: bundle.artifact_version,
    authorizationId: bundle.authorizationId,
    hCommit: bundle.hCommit,
    authorizationBlock: bundle.authorizationBlock,
    blockHash: bundle.blockHash,
    profile: bundle.profile,
    gateEvidence: bundle.gateEvidence,
    plaintextDigest: bundle.plaintextDigest,
    registrySnapshotDigests: {
      commitSnapshot: bundle.registrySnapshotDigests.commitSnapshot,
      authorizationSnapshot: bundle.registrySnapshotDigests.authorizationSnapshot,
    },
  };
}

function profileToJcs(profile: AccessStructureProfile): JcsValue {
  if (profile.kind === "RECIPIENT_K_OF_N") {
    return {
      kind: profile.kind,
      n_conditional: profile.n_conditional,
      k_conditional: profile.k_conditional,
    };
  }
  return { kind: profile.kind };
}

function digestSnapshot(value: JcsValue): Hex32 {
  return asHex32(jcsDigest(value));
}
