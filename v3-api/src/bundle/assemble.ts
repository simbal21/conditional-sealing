import type {
  ArtifactSdRefs,
  ArtifactShredState,
  ChainProofs,
  Hex32,
  IssuerAttestationBlock,
  ProvenanceBlock,
  RegistrySnapshots,
  RevealArtifactBundle,
  SigmaBlock,
} from "../types/reveal-artifact-bundle.js";
import {
  BUNDLE_VERSION_CURRENT,
  PII_STATEMENT_LITERAL,
  REVEAL_ARTIFACT_BUNDLE_TOP_KEYS,
} from "../types/reveal-artifact-bundle.js";
import { jcsDigest } from "./canonicalize-jcs.js";

const ZERO_HEX_32 = `0x${"0".repeat(64)}` as Hex32;

export interface M3LowLevelBundleScaffold {
  readonly artifact_type?: string;
  readonly authorizationId?: Hex32;
  readonly hCommit?: Hex32;
  readonly h_commit?: Hex32;
  readonly digest?: Hex32;
  readonly [key: string]: unknown;
}

export interface AssembleRevealBundleInput {
  readonly authorization: RevealArtifactBundle["authorization"];
  readonly pda: RevealArtifactBundle["pda"];
  readonly recipient: RevealArtifactBundle["recipient"];
  readonly plaintext: RevealArtifactBundle["plaintext"];
  readonly issuer_attestation?: IssuerAttestationBlock;
  readonly provenance?: ProvenanceBlock;
  readonly sigma_block: SigmaBlock;
  readonly chain_proofs: ChainProofs;
  readonly registry_snapshots: RegistrySnapshots;
  readonly shred_state: ArtifactShredState;
  readonly sd_refs: ArtifactSdRefs;
  readonly verification?: Omit<RevealArtifactBundle["verification"], "artifact_bundle_digest">;
  readonly m3_scaffold?: M3LowLevelBundleScaffold;
}

export interface AssembleRevealBundleResult {
  readonly bundle: RevealArtifactBundle;
  readonly artifact_bundle_digest: Hex32;
  readonly canonical_jcs_digest: Hex32;
}

export function assembleRevealArtifactBundle(
  input: AssembleRevealBundleInput,
): AssembleRevealBundleResult {
  assertM3ScaffoldCompatible(input);

  const provisional = orderedBundle({
    ...input,
    verification: {
      artifact_bundle_digest: ZERO_HEX_32,
      verifier_version: input.verification?.verifier_version ?? "s2-5.1-api",
      ...(input.verification?.checks === undefined ? {} : { checks: input.verification.checks }),
    },
  });
  const artifactBundleDigest = jcsDigest(provisional);
  const bundle = orderedBundle({
    ...input,
    verification: {
      artifact_bundle_digest: artifactBundleDigest,
      verifier_version: input.verification?.verifier_version ?? "s2-5.1-api",
      ...(input.verification?.checks === undefined ? {} : { checks: input.verification.checks }),
    },
  });

  assertTopLevelOrder(bundle);
  return {
    bundle,
    artifact_bundle_digest: artifactBundleDigest,
    canonical_jcs_digest: jcsDigest(bundle),
  };
}

function orderedBundle(
  input: AssembleRevealBundleInput & {
    readonly verification: RevealArtifactBundle["verification"];
  },
): RevealArtifactBundle {
  return {
    bundle_version: BUNDLE_VERSION_CURRENT,
    canonicalization: {
      format: "JCS",
      rfc: "RFC8785",
      hash: "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))",
    },
    authorization: input.authorization,
    pda: input.pda,
    recipient: input.recipient,
    plaintext: input.plaintext,
    issuer_attestation: input.issuer_attestation ?? { status: "not_configured" },
    provenance: input.provenance ?? { status: "not_configured" },
    sigma_block: input.sigma_block,
    chain_proofs: input.chain_proofs,
    registry_snapshots: input.registry_snapshots,
    shred_state: input.shred_state,
    sd_refs: input.sd_refs,
    verification: input.verification,
    pii_statement: PII_STATEMENT_LITERAL,
  };
}

function assertTopLevelOrder(bundle: RevealArtifactBundle): void {
  const actual = Object.keys(bundle);
  const expected = [...REVEAL_ARTIFACT_BUNDLE_TOP_KEYS];
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`RevealArtifactBundle top-level key drift: ${actual.join(",")}`);
  }
}

function assertM3ScaffoldCompatible(input: AssembleRevealBundleInput): void {
  const scaffold = input.m3_scaffold;
  if (scaffold === undefined) return;
  if (scaffold.artifact_type !== "RevealArtifactBundle") {
    throw new Error("M3 scaffold drift: artifact_type must be RevealArtifactBundle.");
  }
  if (scaffold.authorizationId !== undefined && scaffold.authorizationId !== input.authorization.authorizationId) {
    throw new Error("M3 scaffold drift: authorizationId mismatch.");
  }
  const scaffoldCommit = scaffold.hCommit ?? scaffold.h_commit;
  if (scaffoldCommit !== undefined && scaffoldCommit !== input.authorization.h_commit) {
    throw new Error("M3 scaffold drift: h_commit mismatch.");
  }
}
