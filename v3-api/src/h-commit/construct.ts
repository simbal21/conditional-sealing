import type { CommitAADInput, CommitContextInput } from "../m1-imports.js";
import {
  ACTIVE_COMMIT_VERSION,
  computeAADDigest,
  computeCommitContextDigest,
} from "../m1-imports.js";
import type { Hex32 } from "./validate.js";
import {
  bytesToHex32,
  hexToBytes32,
  utf8DigestHex32,
  zeroBytes32,
  zeroHex32,
} from "./validate.js";

export type G3Choice = "dcipher" | "drand";
export type G4Phase = 1 | 2;

export interface HCommitPdaFields {
  readonly pda_root: Hex32;
  readonly partner_id: string;
  readonly schema_digest: Hex32;
  readonly g3_choice: G3Choice;
  readonly g4_phase: G4Phase;
  readonly retention_seconds: bigint;
  readonly recipients_root?: Hex32;
  readonly reveal_challenge_window_seconds?: number;
  readonly shred_challenge_window_seconds?: number;
  readonly shred_authority_id?: Hex32;
  readonly conditional_recipients_policy_digest?: Hex32;
  readonly oracle_references_root?: Hex32;
  readonly dsl_version_ref?: Hex32;
  readonly g4_authority_ref?: Hex32;
}

export interface HCommitRequestFields {
  readonly authorizationId: Hex32;
  readonly subject_commitment_v3?: Hex32;
  readonly sigma_subject?: string;
  readonly pre_sigma_session_id?: string;
  readonly endpoint_attestation_digest: Hex32;
  readonly sdMerkleRoot?: Hex32;
  readonly p15_attestations_root?: Hex32;
  readonly conditional_recipients_stanza_count?: number;
  readonly commit_generation?: number;
  readonly composite_identity_digest?: Hex32;
  readonly superseded_commit_ref?: Hex32;
}

export interface HCommitArtifacts {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly aad_digest: Hex32;
  readonly commit_context_digest: Hex32;
  readonly commit_AAD: CommitAADInput;
  readonly commit_context: CommitContextInput;
}

function g3ChoiceToByte(choice: G3Choice): number {
  return choice === "drand" ? 1 : 0;
}

function optionalHex(value: Hex32 | undefined): Uint8Array {
  return value === undefined ? zeroBytes32() : hexToBytes32(value);
}

function partnerIdDigest(partnerId: string): Uint8Array {
  return hexToBytes32(utf8DigestHex32(`partner:${partnerId}`));
}

function sigmaSubjectDigest(input: HCommitRequestFields): Uint8Array {
  if (input.sigma_subject !== undefined && input.sigma_subject.length > 0) {
    return hexToBytes32(utf8DigestHex32(`sigma_subject:${input.sigma_subject}`));
  }
  if (input.pre_sigma_session_id !== undefined && input.pre_sigma_session_id.length > 0) {
    return hexToBytes32(utf8DigestHex32(`pre_sigma_session:${input.pre_sigma_session_id}`));
  }
  return zeroBytes32();
}

export function constructHCommitArtifacts(
  pda: HCommitPdaFields,
  request: HCommitRequestFields,
): HCommitArtifacts {
  const commitAAD: CommitAADInput = {
    authorizationId: hexToBytes32(request.authorizationId),
    pda_root: hexToBytes32(pda.pda_root),
    schema_digest: hexToBytes32(pda.schema_digest),
    partner_id: partnerIdDigest(pda.partner_id),
    commit_version: ACTIVE_COMMIT_VERSION,
    subject_commitment_v3: optionalHex(request.subject_commitment_v3),
    sigma_subject_digest: sigmaSubjectDigest(request),
    recipients_root: optionalHex(pda.recipients_root ?? zeroHex32()),
    p15_attestations_root: optionalHex(request.p15_attestations_root ?? zeroHex32()),
    endpoint_attestation_digest: hexToBytes32(request.endpoint_attestation_digest),
    conditional_recipients_policy_digest: optionalHex(
      pda.conditional_recipients_policy_digest ?? zeroHex32(),
    ),
    sdMerkleRoot: optionalHex(request.sdMerkleRoot ?? zeroHex32()),
    g3_choice: g3ChoiceToByte(pda.g3_choice),
    phase: pda.g4_phase,
    composite_identity_type: 0,
    conditional_recipients_stanza_count: request.conditional_recipients_stanza_count ?? 0,
    plugin_version_digest: hexToBytes32(utf8DigestHex32("cealis-v3-api-m5-phase-b")),
    g4_authority_ref: optionalHex(pda.g4_authority_ref ?? zeroHex32()),
    dsl_version_ref: optionalHex(pda.dsl_version_ref ?? zeroHex32()),
    oracle_references_root: optionalHex(pda.oracle_references_root ?? zeroHex32()),
    superseded_commit_ref: optionalHex(request.superseded_commit_ref ?? zeroHex32()),
    commit_generation: request.commit_generation ?? 0,
  };

  const aadDigestBytes = computeAADDigest(commitAAD);
  const commitContext: CommitContextInput = {
    authorizationId: commitAAD.authorizationId,
    pda_root: commitAAD.pda_root,
    schema_digest: commitAAD.schema_digest,
    aad_digest: aadDigestBytes,
    composite_identity_digest: optionalHex(request.composite_identity_digest ?? zeroHex32()),
    endpoint_attestation_digest: commitAAD.endpoint_attestation_digest,
    retention_window: pda.retention_seconds,
    shred_authority_id: optionalHex(pda.shred_authority_id ?? zeroHex32()),
    recipients_root: commitAAD.recipients_root,
    reveal_challenge_window: request.commit_generation === undefined
      ? (pda.reveal_challenge_window_seconds ?? 0)
      : (pda.reveal_challenge_window_seconds ?? 0),
    shred_challenge_window: pda.shred_challenge_window_seconds ?? 0,
    g3_choice: commitAAD.g3_choice,
    phase: commitAAD.phase,
    commit_version: ACTIVE_COMMIT_VERSION,
  };
  const commitContextDigestBytes = computeCommitContextDigest(commitContext);

  return {
    authorizationId: request.authorizationId,
    h_commit: bytesToHex32(commitContextDigestBytes),
    aad_digest: bytesToHex32(aadDigestBytes),
    commit_context_digest: bytesToHex32(commitContextDigestBytes),
    commit_AAD: commitAAD,
    commit_context: commitContext,
  };
}

