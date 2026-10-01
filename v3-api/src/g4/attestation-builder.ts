import type { G3Choice, G4Phase, Hex32 } from "../h-commit/index.js";
import { jcsDigestHex32, utf8DigestHex32 } from "../h-commit/index.js";
import { buildPhase1Binding, type Phase1Binding } from "./phase1-binding.js";
import { buildPhase2Binding, type Phase2Binding } from "./phase2-binding.js";

export interface RegistrySnapshotRef {
  readonly registry_name: string;
  readonly chain_id: number;
  readonly registry_address: string;
  readonly checked_block: number;
  readonly checked_block_hash: Hex32;
  readonly lookup_key?: string;
  readonly entry_digest: Hex32;
  readonly proof_ref?: string;
}

export interface VerificationCheckResult {
  readonly status: "pass" | "fail";
  readonly checked_block: number;
  readonly checked_block_hash: Hex32;
  readonly code?: string;
  readonly safe_refs?: Record<string, string | number | boolean>;
}

export interface AttestationVerificationChecks {
  readonly lit_assignment: VerificationCheckResult;
  readonly lit_dcap: VerificationCheckResult;
  readonly g3_pubkey: VerificationCheckResult;
  readonly g4_authority: VerificationCheckResult;
}

export interface AttestationPreflight {
  readonly digest: Hex32;
  readonly authorizationIdCandidate: Hex32;
  readonly preflight_context_digest: Hex32;
  readonly commit_block_number: number;
  readonly commit_block_hash: Hex32;
  readonly registry_refs: readonly RegistrySnapshotRef[];
  readonly lit_assignment: {
    readonly authorizationId: Hex32;
    readonly assignment_digest: Hex32;
    readonly assigned_operator_id: string;
    readonly registry_ref: RegistrySnapshotRef;
    readonly assignment_record_ref?: string;
  };
  readonly lit_dcap: {
    readonly quote_digest: Hex32;
    readonly bound_authorizationId: Hex32;
    readonly bound_preflight_context_digest: Hex32;
    readonly bound_block_hash: Hex32;
    readonly tee_vendor_family: string;
    readonly measurement: string;
    readonly user_data_binding_digest?: Hex32;
    readonly registry_ref: RegistrySnapshotRef;
    readonly quote_ref?: string;
  };
  readonly g3_pubkey: {
    readonly network: G3Choice;
    readonly pubkey_digest: Hex32;
    readonly registry_ref: RegistrySnapshotRef;
    readonly committee_id?: string;
    readonly pubkey_ref?: string;
  };
  readonly g4_authority: {
    readonly phase: G4Phase;
    readonly registry_ref: RegistrySnapshotRef;
    readonly phase1?: Phase1Binding;
    readonly phase2?: Phase2Binding;
  };
  readonly verification_checks: AttestationVerificationChecks;
}

export interface G4EndpointAttestationResponse {
  readonly phase: G4Phase;
  readonly pda_id: string;
  readonly authorizationIdCandidate: Hex32;
  readonly preflight_context_digest: Hex32;
  readonly commit_block_number: number;
  readonly commit_block_hash: Hex32;
  readonly attestation_digest: Hex32;
  readonly phase1?: Phase1Binding;
  readonly phase2?: Phase2Binding;
  readonly verification_checks: AttestationVerificationChecks;
  readonly attestation_preflight: AttestationPreflight;
}

export interface BuildG4AttestationInput {
  readonly pda_id: string;
  readonly pda_root: Hex32;
  readonly g3_choice: G3Choice;
  readonly g4_phase: G4Phase;
  readonly authorizationIdCandidate: Hex32;
  readonly preflight_context_digest: Hex32;
  readonly commit_block_number: number;
  readonly commit_block_hash: Hex32;
}

function registryRef(
  registryName: string,
  checkedBlock: number,
  checkedBlockHash: Hex32,
  lookupKey: string,
): RegistrySnapshotRef {
  return {
    registry_name: registryName,
    chain_id: 8453,
    registry_address: "0x0000000000000000000000000000000000000000",
    checked_block: checkedBlock,
    checked_block_hash: checkedBlockHash,
    lookup_key: lookupKey,
    entry_digest: utf8DigestHex32(`${registryName}:${lookupKey}:${String(checkedBlock)}`),
    proof_ref: `${registryName}:${lookupKey}`,
  };
}

function passingCheck(
  checkedBlock: number,
  checkedBlockHash: Hex32,
  safeRefs: Record<string, string | number | boolean>,
): VerificationCheckResult {
  return {
    status: "pass",
    checked_block: checkedBlock,
    checked_block_hash: checkedBlockHash,
    safe_refs: safeRefs,
  };
}

export function buildG4EndpointAttestation(
  input: BuildG4AttestationInput,
): G4EndpointAttestationResponse {
  const litRegistry = registryRef(
    "LitAssignmentRegistry",
    input.commit_block_number,
    input.commit_block_hash,
    input.authorizationIdCandidate,
  );
  const litDcapRegistry = registryRef(
    "LitDcapRegistry",
    input.commit_block_number,
    input.commit_block_hash,
    input.preflight_context_digest,
  );
  const g3Registry = registryRef(
    input.g3_choice === "dcipher" ? "DcipherCommitteeRegistry" : "DrandCommitteeRegistry",
    input.commit_block_number,
    input.commit_block_hash,
    input.pda_root,
  );
  const g4Registry = registryRef(
    "G4AuthorityRegistry",
    input.commit_block_number,
    input.commit_block_hash,
    input.pda_id,
  );
  const checks: AttestationVerificationChecks = {
    lit_assignment: passingCheck(input.commit_block_number, input.commit_block_hash, {
      authorizationId: input.authorizationIdCandidate,
      pda_id: input.pda_id,
    }),
    lit_dcap: passingCheck(input.commit_block_number, input.commit_block_hash, {
      authorizationId: input.authorizationIdCandidate,
      registry_ref: litDcapRegistry.proof_ref ?? "LitDcapRegistry",
    }),
    g3_pubkey: passingCheck(input.commit_block_number, input.commit_block_hash, {
      pda_id: input.pda_id,
      registry_ref: g3Registry.proof_ref ?? "G3Registry",
    }),
    g4_authority: passingCheck(input.commit_block_number, input.commit_block_hash, {
      pda_id: input.pda_id,
      registry_ref: g4Registry.proof_ref ?? "G4AuthorityRegistry",
    }),
  };

  const phase1 = input.g4_phase === 1
    ? buildPhase1Binding({
        binary_hash: utf8DigestHex32(`g4-phase1:${input.pda_id}`),
        effective_block: input.commit_block_number,
      })
    : undefined;
  const phase2 = input.g4_phase === 2
    ? buildPhase2Binding({
        quote_digest: utf8DigestHex32(`g4-phase2-quote:${input.pda_id}`),
        user_data_binding_digest: input.preflight_context_digest,
      })
    : undefined;

  const preflightWithoutDigest = {
    authorizationIdCandidate: input.authorizationIdCandidate,
    preflight_context_digest: input.preflight_context_digest,
    commit_block_number: input.commit_block_number,
    commit_block_hash: input.commit_block_hash,
    registry_refs: [litRegistry, litDcapRegistry, g3Registry, g4Registry],
    lit_assignment: {
      authorizationId: input.authorizationIdCandidate,
      assignment_digest: utf8DigestHex32(`lit-assignment:${input.authorizationIdCandidate}`),
      assigned_operator_id: "lit-operator-synthetic",
      registry_ref: litRegistry,
      assignment_record_ref: litRegistry.proof_ref,
    },
    lit_dcap: {
      quote_digest: utf8DigestHex32(`lit-dcap:${input.preflight_context_digest}`),
      bound_authorizationId: input.authorizationIdCandidate,
      bound_preflight_context_digest: input.preflight_context_digest,
      bound_block_hash: input.commit_block_hash,
      tee_vendor_family: "synthetic-lit-tee",
      measurement: "lit-measurement-synthetic",
      user_data_binding_digest: input.preflight_context_digest,
      registry_ref: litDcapRegistry,
      quote_ref: litDcapRegistry.proof_ref,
    },
    g3_pubkey: {
      network: input.g3_choice,
      pubkey_digest: utf8DigestHex32(`g3-pubkey:${input.g3_choice}:${input.pda_root}`),
      registry_ref: g3Registry,
      committee_id: `${input.g3_choice}-committee-synthetic`,
      pubkey_ref: g3Registry.proof_ref,
    },
    g4_authority: {
      phase: input.g4_phase,
      registry_ref: g4Registry,
      phase1,
      phase2,
    },
    verification_checks: checks,
  } satisfies Omit<AttestationPreflight, "digest">;
  const digest = jcsDigestHex32(preflightWithoutDigest);
  const attestationPreflight: AttestationPreflight = {
    digest,
    ...preflightWithoutDigest,
  };

  return {
    phase: input.g4_phase,
    pda_id: input.pda_id,
    authorizationIdCandidate: input.authorizationIdCandidate,
    preflight_context_digest: input.preflight_context_digest,
    commit_block_number: input.commit_block_number,
    commit_block_hash: input.commit_block_hash,
    attestation_digest: digest,
    phase1,
    phase2,
    verification_checks: checks,
    attestation_preflight: attestationPreflight,
  };
}

