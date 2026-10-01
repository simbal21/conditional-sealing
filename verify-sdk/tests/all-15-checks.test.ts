import { describe, expect, it } from "vitest";
import { verifyArtifactBundle } from "../src/index.js";
import { VERIFY_ARTIFACT_CHECK_NAMES, type Hex32, type RevealArtifactBundle, type VerifyArtifactCheckName } from "../src/types.js";
import { computeArtifactBundleDigest, ZERO_HEX32 } from "../src/checks/canonicalization.js";

describe("all 15 artifact checks", () => {
  it("runs every named check and passes a fully populated bundle", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      // Freshness check (security-audit-2026-05-14 TS-API-F-03) defaults to
      // `skipped` without this option. Pass a generous window for the
      // "all checks pass" assertion below; freshness-specific cases follow.
      maxArtifactAgeSeconds: 86_400,
    });
    expect(Object.keys(result.checks).sort()).toEqual([...VERIFY_ARTIFACT_CHECK_NAMES].sort());
    for (const name of VERIFY_ARTIFACT_CHECK_NAMES) {
      expect(result.checks[name].status, name).toBe("pass");
    }
  });

  it("freshness check ENFORCES 24h default when maxArtifactAgeSeconds is not set (R2b-3 TS-API-F-03: default-on, opt-in DELETED)", async () => {
    // R2b-3 (2026-05-21): omitting `maxArtifactAgeSeconds` no longer
    // silently skips the check. It now enforces a 24h
    // (DEFAULT_FRESHNESS_MAX_AGE_SECONDS = 86_400s) window. The fresh
    // bundle (finalized_at 2026-05-11T00:02 vs now 2026-05-11T00:03,
    // ~1 minute old) is well within 24h → PASS.
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      // intentionally omit maxArtifactAgeSeconds AND disableFreshnessCheck
    });
    expect(result.checks.freshness.status).toBe("pass");
    expect(result.checks.freshness.code).toBe("FRESHNESS.PASS");
  });

  it("freshness check ENFORCES 24h default — stale bundle (> 24h old) FAILS when option omitted (R2b-3 named-attack probe)", async () => {
    // R2b-3 default-on closure: a bundle older than the 24h default is
    // refused, even when the caller omits maxArtifactAgeSeconds entirely.
    // Pre-R2b-3, this exact attack — captured legitimate bundle replayed
    // 25h+ later against a caller who forgot the option — would have
    // silently passed via FRESHNESS.SKIPPED_NO_OPTION → overall=pass.
    // This is the named "captured-and-replayed-after-default" attack probe.
    const result = await verifyArtifactBundle(validBundle(), {
      // 25 hours after finalized_at — past the 24h default window.
      now: new Date("2026-05-12T01:02:00.000Z"),
      // intentionally omit maxArtifactAgeSeconds AND disableFreshnessCheck
    });
    expect(result.checks.freshness.status).toBe("fail");
    expect(result.checks.freshness.code).toBe("FRESHNESS.STALE");
    expect(result.overall).toBe("fail");
  });

  it("freshness check SKIPS only when disableFreshnessCheck === true (explicit opt-OUT)", async () => {
    // The only path that returns `skipped` is the explicit opt-OUT flag.
    // Caller MUST have set the boolean to `true` (not omitted, not `false`)
    // — type-discriminated audit-greppable. Same shape as F-08
    // canonicalAddressPin's no-opt-in-via-undefined rule.
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      disableFreshnessCheck: true,
    });
    expect(result.checks.freshness.status).toBe("skipped");
    expect(result.checks.freshness.code).toBe("FRESHNESS.SKIPPED_EXPLICIT_OPT_OUT");
  });

  it("freshness check is NOT skipped when disableFreshnessCheck === false (explicit-false ≠ opt-out)", async () => {
    // The skip path requires the flag === true. Setting it explicitly to
    // false (or omitting it, see prior tests) runs the check at the
    // default window. This pins the type-discriminated boolean semantic
    // so an attacker can't smuggle a `disableFreshnessCheck: false` value
    // expecting the check to skip.
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      disableFreshnessCheck: false,
    });
    expect(result.checks.freshness.status).toBe("pass");
    expect(result.checks.freshness.code).toBe("FRESHNESS.PASS");
  });

  it("disableFreshnessCheck === true skips even on a stale bundle (the opt-OUT really is opt-OUT)", async () => {
    // Behavioral proof that the explicit opt-OUT bypasses the freshness
    // check even when the bundle is clearly stale (25h+ old vs the 24h
    // default). The skip is unconditional — the caller is taking explicit
    // responsibility for archival/audit replay semantics. Defense-in-depth
    // for legitimate-use-case correctness.
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-12T01:02:00.000Z"), // 25h after finalized_at
      disableFreshnessCheck: true,
    });
    expect(result.checks.freshness.status).toBe("skipped");
    expect(result.checks.freshness.code).toBe("FRESHNESS.SKIPPED_EXPLICIT_OPT_OUT");
  });

  it("freshness check fails on stale bundle (replay defense)", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      // 1 day after finalized_at with a 60-second window -> stale
      now: new Date("2026-05-12T00:02:00.000Z"),
      maxArtifactAgeSeconds: 60,
    });
    expect(result.checks.freshness.status).toBe("fail");
    expect(result.checks.freshness.code).toBe("FRESHNESS.STALE");
    expect(result.overall).toBe("fail");
  });

  it("freshness check fails on invalid maxArtifactAgeSeconds (0)", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      maxArtifactAgeSeconds: 0,
    });
    expect(result.checks.freshness.status).toBe("fail");
    expect(result.checks.freshness.code).toBe("FRESHNESS.INVALID_OPTION");
  });

  it("freshness check fails on invalid maxArtifactAgeSeconds (negative)", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      maxArtifactAgeSeconds: -1,
    });
    expect(result.checks.freshness.status).toBe("fail");
    expect(result.checks.freshness.code).toBe("FRESHNESS.INVALID_OPTION");
  });

  it("freshness check fails on invalid maxArtifactAgeSeconds (NaN)", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      maxArtifactAgeSeconds: Number.NaN,
    });
    expect(result.checks.freshness.status).toBe("fail");
    expect(result.checks.freshness.code).toBe("FRESHNESS.INVALID_OPTION");
  });

  it("freshness check fails on missing finalized_at", async () => {
    const bundle = cloneBundle();
    (bundle.authorization as { finalized_at: string }).finalized_at = "";
    const result = await verifyArtifactBundle(finalizeBundle(bundle), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      maxArtifactAgeSeconds: 86_400,
    });
    expect(result.checks.freshness.status).toBe("fail");
    expect(result.checks.freshness.code).toBe("FRESHNESS.FINALIZED_AT_MISSING");
  });

  it("freshness check fails on malformed finalized_at", async () => {
    const bundle = cloneBundle();
    (bundle.authorization as { finalized_at: string }).finalized_at = "not-a-timestamp";
    const result = await verifyArtifactBundle(finalizeBundle(bundle), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      maxArtifactAgeSeconds: 86_400,
    });
    expect(result.checks.freshness.status).toBe("fail");
    expect(result.checks.freshness.code).toBe("FRESHNESS.FINALIZED_AT_MALFORMED");
  });

  it("freshness check fails on future timestamp beyond clock-skew tolerance", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      // `now` is 5 minutes BEFORE finalized_at — way outside the 60s skew
      now: new Date("2026-05-10T23:57:00.000Z"),
      maxArtifactAgeSeconds: 86_400,
    });
    expect(result.checks.freshness.status).toBe("fail");
    expect(result.checks.freshness.code).toBe("FRESHNESS.FUTURE_TIMESTAMP");
  });

  it("freshness check accepts small clock skew (≤60s in the future)", async () => {
    const result = await verifyArtifactBundle(validBundle(), {
      // `now` is 30s BEFORE finalized_at (within 60s tolerance)
      now: new Date("2026-05-11T00:01:30.000Z"),
      maxArtifactAgeSeconds: 86_400,
    });
    expect(result.checks.freshness.status).toBe("pass");
    expect(result.checks.freshness.code).toBe("FRESHNESS.PASS");
  });

  it.each(failCases)("fails %s on targeted drift", async (name, mutate, refreshDigest) => {
    const bundle = cloneBundle();
    mutate(bundle);
    const drifted = refreshDigest ? finalizeBundle(bundle) : bundle;
    const result = await verifyArtifactBundle(drifted, {
      now: new Date("2026-05-11T00:03:00.000Z"),
      expectedRecipientRef: name === "recipientSelector" ? "recipient-b" : undefined,
    });
    expect(result.checks[name].status).toBe("fail");
  });

  it.each(extraFailCases)("returns %s for %s branch coverage", async (expectedCode, name, mutate) => {
    const bundle = cloneBundle();
    mutate(bundle);
    const result = await verifyArtifactBundle(finalizeBundle(bundle), {
      now: new Date("2026-05-11T00:03:00.000Z"),
    });
    expect(result.checks[name].code).toBe(expectedCode);
  });

  it.each(skippedCases)("skips %s when spec says not configured", async (name, mutate) => {
    const bundle = cloneBundle();
    mutate(bundle);
    const result = await verifyArtifactBundle(finalizeBundle(bundle), {
      now: new Date("2026-05-11T00:03:00.000Z"),
    });
    expect(result.checks[name].status).toBe("skipped");
  });
});

type BundleMutator = (bundle: RevealArtifactBundle) => void;

const failCases: ReadonlyArray<readonly [VerifyArtifactCheckName, BundleMutator, boolean]> = [
  ["canonicalization", (bundle) => { bundle.verification.artifact_bundle_digest = hex(999); }, false],
  ["chainProof", (bundle) => { bundle.chain_proofs.reveal_authorized_block = 201; }, true],
  ["pdaRoot", (bundle) => { bundle.pda.pda_root = hex(99); }, true],
  ["registrySnapshots", (bundle) => { bundle.registry_snapshots.authorization_block = 199; }, true],
  ["endpointAttestation", (bundle) => { bundle.sigma_block.sigma_g4.phase = undefined; }, true],
  ["issuerAttestation", (bundle) => { if (bundle.issuer_attestation.status === "present") bundle.issuer_attestation.signature = ""; }, true],
  ["provenance", (bundle) => { if (bundle.provenance.status === "present") bundle.provenance.field_attestations[0]!.field_hash = "0xabc"; }, true],
  ["sigmaSubject", (bundle) => { bundle.sigma_block.sigma_subject = "not-hex" as `0x${string}`; }, true],
  ["sigmaLit", (bundle) => { bundle.sigma_block.sigma_lit.sigma = "0x"; }, true],
  ["sigmaG3", (bundle) => { bundle.sigma_block.sigma_g3.authority_ref = "0xabc"; }, true],
  ["sigmaG4", (bundle) => { bundle.sigma_block.sigma_g4.phase = 3 as 1; }, true],
  ["sigmaConditional", (bundle) => { bundle.sigma_block.sigma_conditional = [{ sigma: "0x", authority_ref: hex(14), public_after_reveal: true }]; }, true],
  ["shredState", (bundle) => { bundle.shred_state.shred_state = "finalized"; }, true],
  ["recipientSelector", () => undefined, true],
  ["sdRefs", (bundle) => { bundle.sd_refs = { status: "present" }; }, true],
];

const skippedCases: ReadonlyArray<readonly [VerifyArtifactCheckName, BundleMutator]> = [
  ["issuerAttestation", (bundle) => { bundle.issuer_attestation = { status: "not_configured" }; }],
  ["provenance", (bundle) => { bundle.provenance = { status: "not_configured" }; }],
  ["sigmaSubject", (bundle) => { delete bundle.sigma_block.sigma_subject; }],
  ["sigmaConditional", (bundle) => { bundle.sigma_block.sigma_conditional = []; }],
  ["sdRefs", (bundle) => { bundle.sd_refs = { status: "not_configured" }; }],
];

const extraFailCases: ReadonlyArray<readonly [string, VerifyArtifactCheckName, BundleMutator]> = [
  ["CHAIN_PROOF.MALFORMED_HEX", "chainProof", (bundle) => { bundle.chain_proofs.commit_tx_hash = "0xabc"; }],
  ["CHAIN_PROOF.AUTHORIZATION_BLOCK_HASH_MISMATCH", "chainProof", (bundle) => { bundle.chain_proofs.reveal_authorized_block_hash = hex(99); }],
  ["CHAIN_PROOF.RECEIPT_BLOCK_MISMATCH", "chainProof", (bundle) => { bundle.chain_proofs.receipt_proof.block_number = 201; }],
  ["CHAIN_PROOF.RECEIPT_BLOCK_HASH_MISMATCH", "chainProof", (bundle) => { bundle.chain_proofs.receipt_proof.block_hash = hex(99); }],
  ["CHAIN_PROOF.LOG_INDEX_MISMATCH", "chainProof", (bundle) => { bundle.chain_proofs.receipt_proof.log_index = 1; }],
  ["CHAIN_PROOF.CONDITION_REF_MISMATCH", "chainProof", (bundle) => { bundle.chain_proofs.conditionRef = hex(99); }],
  ["CHAIN_PROOF.CHALLENGE_WINDOW_OPEN", "chainProof", (bundle) => { bundle.authorization.challenge_window_expired_at = "2026-05-11T00:10:00.000Z"; }],
  ["PDA_ROOT.MALFORMED", "pdaRoot", (bundle) => { bundle.pda.pda_root = "0xabc"; }],
  ["REGISTRY_SNAPSHOTS.AUTHORIZATION_HASH_MISMATCH", "registrySnapshots", (bundle) => { bundle.registry_snapshots.authorization_block_hash = hex(99); }],
  ["REGISTRY_SNAPSHOTS.MALFORMED_REF", "registrySnapshots", (bundle) => { bundle.registry_snapshots.registry_contracts.condition_engine!.entry_digest = "0xabc"; }],
  ["ENDPOINT_ATTESTATION.G4_AUTHORITY_REF_MISSING", "endpointAttestation", (bundle) => { bundle.sigma_block.sigma_g4.authority_ref = "0xabc"; }],
  ["ENDPOINT_ATTESTATION.ATTESTATION_REF_MALFORMED", "endpointAttestation", (bundle) => { bundle.sigma_block.sigma_g4.attestation_ref = "0xabc"; }],
  ["ISSUER_ATTESTATION.REGISTRY_REF_MALFORMED", "issuerAttestation", (bundle) => {
    if (bundle.issuer_attestation.status === "present") bundle.issuer_attestation.issuer_registry_ref.entry_digest = "0xabc";
  }],
  ["PROVENANCE.MALFORMED", "provenance", (bundle) => {
    if (bundle.provenance.status === "present") bundle.provenance.p15_attestations_root = "0xabc";
  }],
  ["PROVENANCE.REGISTRY_REF_MALFORMED", "provenance", (bundle) => {
    if (bundle.provenance.status === "present") bundle.provenance.attestor_registry_ref.entry_digest = "0xabc";
  }],
  ["PROVENANCE.FIELD_ATTESTATION_MALFORMED", "provenance", (bundle) => {
    if (bundle.provenance.status === "present") bundle.provenance.field_attestations[0]!.signature_alg = "";
  }],
  ["SIGMA_SUBJECT.MALFORMED", "sigmaSubject", (bundle) => { bundle.sigma_block.sigma_subject = "0x"; }],
  ["SIGMA_LIT.NOT_PUBLIC_AFTER_REVEAL", "sigmaLit", (bundle) => { bundle.sigma_block.sigma_lit.public_after_reveal = false as true; }],
  ["SIGMA_LIT.ATTESTATION_REF_MALFORMED", "sigmaLit", (bundle) => { bundle.sigma_block.sigma_lit.attestation_ref = "0xabc"; }],
  ["SIGMA_CONDITIONAL.STANZA_INDEX_MALFORMED", "sigmaConditional", (bundle) => {
    bundle.sigma_block.sigma_conditional = [{ sigma: "0x44", authority_ref: hex(14), stanza_index: 1.5, public_after_reveal: true }];
  }],
  ["SHRED_STATE.H_COMMIT_MISMATCH", "shredState", (bundle) => { bundle.shred_state.h_commit = hex(99); }],
  ["SHRED_STATE.CHECKED_HASH_MALFORMED", "shredState", (bundle) => { bundle.shred_state.checked_at_block_hash = "0xabc"; }],
  ["RECIPIENT_SELECTOR.SCHEMA_SELECTOR_MALFORMED", "recipientSelector", (bundle) => { bundle.recipient.schema_selector_digest = "0xabc"; }],
  ["RECIPIENT_SELECTOR.SCHEMA_SELECTOR_MISMATCH", "recipientSelector", (bundle) => { bundle.plaintext.schema_selector_digest = hex(99); }],
  ["SD_REFS.UNKNOWN_STATUS", "sdRefs", (bundle) => { bundle.sd_refs = { status: "unknown" as "present" }; }],
];

function validBundle(): RevealArtifactBundle {
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
    recipient: { recipient_ref: "recipient-a", recipient_pubkey_id: "pubkey-a", schema_selector_digest: hex(6) },
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
      sigma_conditional: [{ sigma: "0x44", authority_ref: hex(14), stanza_index: 0, public_after_reveal: true }],
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
      registry_contracts: { condition_engine: registryRef("condition_engine") },
      pda_registry: registryRef("pda"),
      condition_module_registry: registryRef("condition_module"),
      gate_authority_registries: { lit: registryRef("lit"), g3: registryRef("g3"), g4: registryRef("g4") },
      shred_registry: registryRef("shred"),
      issuer_registry: registryRef("issuer"),
      attestor_registry: registryRef("attestor"),
      sd_registry: registryRef("sd"),
    },
    shred_state: { h_commit: hex(2), shred_state: "not_shredded", checked_at_block: 200, checked_at_block_hash: hex(3) },
    sd_refs: { status: "present", sdMerkleRoot: hex(101), disclosure_refs: ["sd://artifact"], revocation_refs: ["sd://revocation"] },
    verification: { artifact_bundle_digest: ZERO_HEX32, verifier_version: "test", checks: { sdRefs: "present" } },
    pii_statement: "recipient_filtered_plaintext_after_valid_reveal",
  });
}

function finalizeBundle(bundle: RevealArtifactBundle): RevealArtifactBundle {
  return { ...bundle, verification: { ...bundle.verification, artifact_bundle_digest: computeArtifactBundleDigest(bundle) } };
}

function cloneBundle(bundle: RevealArtifactBundle = validBundle()): RevealArtifactBundle {
  return JSON.parse(JSON.stringify(bundle)) as RevealArtifactBundle;
}

function hex(n: number): Hex32 {
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
