import { describe, expect, it } from "vitest";
import { verifyArtifactBundle } from "../src/index.js";
import type { Hex32, RevealArtifactBundle } from "../src/types.js";
import { computeArtifactBundleDigest, ZERO_HEX32 } from "../src/checks/canonicalization.js";

describe("verifyArtifactBundle", () => {
  it("passes a fully populated offline artifact bundle", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      expectedRecipientRef: "recipient-a",
    });
    expect(result.overall).toBe("pass");
    expect(result.artifact_bundle_digest).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.checks.canonicalization.status).toBe("pass");
    expect(result.checks.sigmaConditional.status).toBe("pass");
  });

  it("fails with useful safe refs when expected recipient does not match", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      expectedRecipientRef: "recipient-b",
    });
    expect(result.overall).toBe("fail");
    expect(result.checks.recipientSelector).toMatchObject({
      status: "fail",
      code: "RECIPIENT_SELECTOR.UNEXPECTED_RECIPIENT",
    });
    expect(result.safe_refs).toMatchObject({
      authorizationId: hex(1),
      h_commit: hex(2),
      pda_root: hex(5),
      authorization_block: 200,
    });
  });

  it("fails online chain proof mode unless caller supplies a partner RPC URL", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      requireOnlineRegistryChecks: true,
    });
    expect(result.overall).toBe("fail");
    expect(result.checks.chainProof.code).toBe("CHAIN_PROOF.RPC_URL_REQUIRED");
  });
});

export function validBundle(): RevealArtifactBundle {
  return finalizeBundle({
    bundle_version: "s2-5.1",
    canonicalization: {
      format: "JCS",
      rfc: "RFC8785",
      hash: "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))",
    },
    authorization: {
      authorizationId: hex(1),
      h_commit: hex(2),
      commit_version: "0x0302",
      authorization_block: 200,
      authorization_block_hash: hex(3),
      authorization_timestamp: "2026-05-11T00:00:00.000Z",
      conditionRef: hex(4),
      challenge_window_seconds: 60,
      challenge_window_expired_at: "2026-05-11T00:01:00.000Z",
      finalized_at: "2026-05-11T00:02:00.000Z",
    },
    pda: {
      pda_id: "pda-demo",
      pda_version: "1",
      pda_root: hex(5),
      trust_tier: "tier_b",
      operational_class: "regulated",
    },
    recipient: {
      recipient_ref: "recipient-a",
      recipient_pubkey_id: "pubkey-a",
      schema_selector_digest: hex(6),
    },
    plaintext: {
      schema_selector_digest: hex(6),
      schema_digest: hex(7),
      content_encoding: "application/json",
      fields: { legal_name: "Alice" },
      field_hashes: { legal_name: hex(8) },
    },
    issuer_attestation: {
      status: "present",
      issuer_id: "issuer-a",
      issuer_registry_ref: registryRef("issuer"),
      issuer_signing_key_id: "issuer-key-a",
      signature_alg: "ed25519",
      signed_payload_digest: hex(80),
      signature: "issuer-signature",
      subject_commitment_v3: hex(81),
      person_key_ref: "person-key-a",
    },
    provenance: {
      status: "present",
      p15_attestations_root: hex(90),
      attestor_registry_ref: registryRef("attestor"),
      field_attestations: [
        {
          field_path: "legal_name",
          field_hash: hex(8),
          attestor_id: "attestor-a",
          attestor_signing_key_id: "attestor-key-a",
          signature_alg: "ed25519",
          signed_payload_digest: hex(91),
          signature: "attestor-signature",
          merkle_proof: [hex(92)],
        },
      ],
    },
    sigma_block: {
      sigma_subject: "0x1234",
      sigma_lit: { sigma: "0x11", authority_ref: hex(11), public_after_reveal: true },
      sigma_g3: { sigma: "0x22", authority_ref: hex(12), variant: "dcipher", public_after_reveal: true },
      sigma_g4: { sigma: "0x33", authority_ref: hex(13), phase: 2, public_after_reveal: true },
      sigma_conditional: [
        { sigma: "0x44", authority_ref: hex(14), stanza_index: 0, public_after_reveal: true },
      ],
    },
    chain_proofs: {
      chain_id: 8453,
      condition_engine_address: "0x0000000000000000000000000000000000000001",
      reveal_authorized_emitter: "0x0000000000000000000000000000000000000001",
      reveal_authorized_event_signature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
      reveal_authorized_topics: [hex(1), hex(2), hex(5)],
      receipt_proof: { proof_type: "mock_receipt", block_number: 200, block_hash: hex(3), log_index: 0 },
      commit_tx_hash: hex(20),
      commit_block: 100,
      commit_block_hash: hex(21),
      reveal_authorized_tx_hash: hex(22),
      reveal_authorized_log_index: 0,
      reveal_authorized_block: 200,
      reveal_authorized_block_hash: hex(3),
      base_finality_confirmations: 32,
      finalized_at: "2026-05-11T00:02:00.000Z",
      challenge_window_expired_at: "2026-05-11T00:01:00.000Z",
      conditionRef: hex(4),
      shred_registry_state_at_reveal: "not_shredded",
    },
    registry_snapshots: {
      authorization_block: 200,
      authorization_block_hash: hex(3),
      registry_contracts: {
        condition_engine: registryRef("condition_engine"),
      },
      pda_registry: registryRef("pda"),
      condition_module_registry: registryRef("condition_module"),
      gate_authority_registries: { lit: registryRef("lit"), g3: registryRef("g3"), g4: registryRef("g4") },
      shred_registry: registryRef("shred"),
      issuer_registry: registryRef("issuer"),
      attestor_registry: registryRef("attestor"),
      sd_registry: registryRef("sd"),
    },
    shred_state: {
      h_commit: hex(2),
      shred_state: "not_shredded",
      checked_at_block: 200,
      checked_at_block_hash: hex(3),
    },
    sd_refs: {
      status: "present",
      sdMerkleRoot: hex(101),
      disclosure_refs: ["sd://artifact"],
      revocation_refs: ["sd://revocation"],
    },
    verification: {
      artifact_bundle_digest: ZERO_HEX32,
      verifier_version: "test",
      checks: { sdRefs: "present" },
    },
    pii_statement: "recipient_filtered_plaintext_after_valid_reveal",
  });
}

export function finalizeBundle(bundle: RevealArtifactBundle): RevealArtifactBundle {
  return {
    ...bundle,
    verification: {
      ...bundle.verification,
      artifact_bundle_digest: computeArtifactBundleDigest(bundle),
    },
  };
}

export function cloneBundle(bundle: RevealArtifactBundle = validBundle()): RevealArtifactBundle {
  return JSON.parse(JSON.stringify(bundle)) as RevealArtifactBundle;
}

export function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}

function registryRef(name: string) {
  return {
    registry_name: name,
    chain_id: 8453,
    registry_address: "0x0000000000000000000000000000000000000001",
    checked_block: 200,
    checked_block_hash: hex(3),
    entry_digest: hex(70),
  };
}
