import { describe, expect, it } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { createRequire } from "node:module";

import {
  InMemoryRevocationRegistryClient,
  SdSdkError,
  SdSdkErrorCode,
  ZERO_HEX_32,
  assertClaimNotExpired,
  assertPublicInputsMatch,
  normalizeScalarHex,
  recomputePublicInputs,
  verifyBindingMode,
  verifyCleartextField,
  verifyClaim,
  verifyMerklePath,
  verifySdBundle,
  type EscrowCommitReference,
  type PdaSdConfig,
  type SdBundle,
  type SdMerklePathElement,
  type VerifierRegistryClient,
} from "../index.js";

const h = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as const;
const now = new Date("2026-05-13T00:00:00Z");
const future = Math.floor(now.getTime() / 1000) + 60;
const auth = h(1);
const claimId = h(7);
const disclosureId = h(8);
const verifierRef = h(6);

// ── D1 (SD-MERKLE-001): real producer-fidelity Merkle fixture ────────────────
// The default cleartext item below must drive verifyCleartextField all the way
// through the §5.1 leaf recompute + Poseidon3 path walk to a REAL root. The
// pre-D1-fix fixture used field_commitment=root, merkle_path=[], sdMerkleRoot=root,
// which only "passed" because the old verifier compared the raw field_commitment
// against the root. After the fix the walk starts from the recomputed Poseidon5
// leaf, so the fixture is rebuilt here with the SAME §5.1 Poseidon5 leaf /
// Poseidon3 node / Poseidon5 padding construction the producer uses
// (`v3-sd/src/merkle/tree.ts`), reusing the producer-captured 3-leaf
// fixture from tests/verify-cleartext-field-leaf.test.ts (HEAD e87c108).
type PoseidonFn = ((inputs: ReadonlyArray<bigint>) => Uint8Array) & {
  F: { toObject(value: Uint8Array): bigint };
};
const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const sdRequire = createRequire(import.meta.url);
const { buildPoseidon } = sdRequire("circomlibjs") as { buildPoseidon: () => Promise<PoseidonFn> };
const poseidon: PoseidonFn = await buildPoseidon();
function os2ipMod(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc % BN254_PRIME;
}
// tag_merkle_scalar = OS2IP(TAG_SD_MERKLE_V3) mod p; TAG_SD_MERKLE_V3 = keccak256("CEALIS_SD_MERKLE_V3")
const TAG_MERKLE = os2ipMod(keccak_256(utf8ToBytes("CEALIS_SD_MERKLE_V3")));
const leafScalar = (field_index: bigint, field_id: bigint, field_commitment: bigint, policy: bigint): bigint =>
  poseidon.F.toObject(poseidon([TAG_MERKLE, field_index, field_id, field_commitment, policy]));
const nodeScalar = (left: bigint, right: bigint): bigint => poseidon.F.toObject(poseidon([TAG_MERKLE, left, right]));
const paddingScalar = (j: bigint): bigint => poseidon.F.toObject(poseidon([TAG_MERKLE, j, 0n, 0n, 0n]));
const toScalarHex = (v: bigint) => `0x${v.toString(16).padStart(64, "0")}` as const;

// Three real leaves -> depth 2, target 4 (one padding leaf at j=3). leaf0 is the
// cleartext disclosure under test: field_index 0, field_id 0x05 (== h(5) mod p),
// field_commitment FC0, policy 1 (cleartext) — matching pda.fields[0] below.
const FC0 = 111n;
const leaf0 = leafScalar(0n, 0x05n, FC0, 1n);
const leaf1 = leafScalar(1n, 0x06n, 222n, 2n);
const leaf2 = leafScalar(2n, 0x07n, 333n, 1n);
const pad3 = paddingScalar(3n);
const paddedLeaves = [leaf0, leaf1, leaf2, pad3];
const level1 = [nodeScalar(paddedLeaves[0]!, paddedLeaves[1]!), nodeScalar(paddedLeaves[2]!, paddedLeaves[3]!)];
const ROOT_SCALAR = nodeScalar(level1[0]!, level1[1]!);
// Producer-captured anchor (HEAD e87c108) — identical fixture to verify-merkle-poseidon.test.ts.
const EXPECTED_ROOT = "0x0cbaf27de5735f4afe70c042c6e93d500c2778adea11933ba7994b9d9912894f";
const root = toScalarHex(ROOT_SCALAR);
// Path for leaf 0 (left child at both levels -> direction 0 at every step).
const FIELD_COMMITMENT_0 = toScalarHex(FC0);
const PATH0: SdMerklePathElement[] = [
  { sibling: toScalarHex(paddedLeaves[1]!), direction: 0 },
  { sibling: toScalarHex(level1[1]!), direction: 0 },
];
const pda: PdaSdConfig = {
  sd_enabled: true,
  ingestion_mode: "MODE_A",
  fields: [{ field_id: h(5), field_index: 0, field_type_code: 2, policy: "cleartext" }],
  claims: [{ claim_id: claimId, claim_type: "range", field_ids: [h(5)], expected_public_inputs: ["1", "2"], public_input_schema_digest: h(44) }],
};
const escrow: EscrowCommitReference = {
  commit_version: "0x0302",
  authorizationId: auth,
  h_commit: h(2),
  pda_root: h(3),
  partner_id: h(4),
  pda_id: h(10),
  pda_version: "1",
  schema_digest: h(11),
  authorizationBlock: 123n,
  commit_AAD: { sdMerkleRoot: root },
};
const verifierRegistry: VerifierRegistryClient = {
  getVerifierAt: () => ({ publicInputSchemaDigest: h(44), verifyProof: () => true }),
};

function bundle(overrides: Partial<SdBundle> = {}): SdBundle {
  return {
    sd_version: "s2-7-1.0",
    status: "complete",
    authorizationId: auth,
    h_commit: h(2),
    pda_root: h(3),
    partner_id: h(4),
    pda_id: h(10),
    pda_version: "1",
    schema_digest: h(11),
    sdMerkleRoot: root,
    sd_salt_context_digest: h(12),
    sd_plan_digest: h(13),
    sd_bundle_digest: h(14),
    rootBindingLevel: "commit_AAD",
    generated_at: "2026-05-13T00:00:00.000Z",
    cleartext: [
      {
        field_id: h(5),
        field_type_code: 2,
        value: 37,
        field_commitment: FIELD_COMMITMENT_0,
        policy_code: 1,
        merkle_path: PATH0,
        opening_mode: "cleartext_zk_opened",
        opening_proof: {
          proof_system: "plonk-bn254",
          verifier_ref: verifierRef,
          proof: h(15),
          public_inputs: ["37", "0", "0"],
          public_input_schema_digest: h(44),
        },
      },
    ],
    claims: [
      {
        claim_id: claimId,
        claim_type: "range",
        field_ids: [h(5)],
        verifier_ref: verifierRef,
        proof: h(16),
        public_inputs: ["1", "2"],
        expiry_timestamp: future,
        disclosure_id: disclosureId,
      },
    ],
    failures: [],
    ...overrides,
  };
}

describe("verifySdBundle", () => {
  it("inline Merkle reconstruction reproduces the producer's captured root byte-for-byte", () => {
    // Drift guard: if either the reconstruction or the producer §5.1 formula changes,
    // this anchor breaks before the end-to-end cleartext assertions silently rot.
    expect(root).toBe(EXPECTED_ROOT);
  });

  it("accepts a complete bundle with caller-supplied verifier and revocation clients", async () => {
    const result = await verifySdBundle({
      escrowCommit: escrow,
      sdBundle: bundle(),
      pdaSdConfig: pda,
      verifierRegistry,
      revocationRegistry: new InMemoryRevocationRegistryClient(),
      now,
    });
    expect(result.status).toBe("valid");
    expect(result.acceptedClaims).toEqual([claimId]);
    expect(result.acceptedCleartextFields).toEqual([h(5)]);
  });

  it("returns partial with machine-readable rejected items", async () => {
    const result = await verifySdBundle({
      escrowCommit: escrow,
      sdBundle: bundle({ claims: [{ ...bundle().claims[0]!, public_inputs: ["9"] }] }),
      pdaSdConfig: pda,
      verifierRegistry,
      revocationRegistry: new InMemoryRevocationRegistryClient(),
      now,
    });
    expect(result.status).toBe("partial");
    expect(result.rejectedClaims[0]?.error).toBe(SdSdkErrorCode.PUBLIC_INPUT_MISMATCH);
  });

  it("covers disabled and failed-before-root modes", async () => {
    const disabled = await verifySdBundle({
      escrowCommit: { ...escrow, commit_AAD: { sdMerkleRoot: ZERO_HEX_32 } },
      pdaSdConfig: { ...pda, sd_enabled: false, fields: [], claims: [] },
      sdBundle: bundle({ status: "not_configured", sdMerkleRoot: ZERO_HEX_32, cleartext: [], claims: [] }),
      verifierRegistry,
      revocationRegistry: new InMemoryRevocationRegistryClient(),
      now,
    });
    const failed = await verifySdBundle({
      escrowCommit: { ...escrow, commit_AAD: { sdMerkleRoot: ZERO_HEX_32 } },
      pdaSdConfig: pda,
      sdBundle: bundle({ status: "failed", sdMerkleRoot: ZERO_HEX_32 }),
      verifierRegistry,
      revocationRegistry: new InMemoryRevocationRegistryClient(),
      now,
    });
    expect(disabled.status).toBe("valid");
    expect(failed.status).toBe("invalid");
  });
});

describe("component failure modes", () => {
  it("rejects binding, Mode B, context, expiry, revocation, verifier, and encoding failures", async () => {
    expect(() => verifyBindingMode({ ...escrow, commit_version: "0x0301" as "0x0302" }, pda, bundle())).toThrow(SdSdkError);
    expect(() => verifyBindingMode({ ...escrow, commit_AAD: { sdMerkleRoot: h(99) } }, pda, bundle())).toThrow(SdSdkError);
    expect(() => verifyBindingMode({ ...escrow, commit_AAD: { sdMerkleRoot: ZERO_HEX_32 } }, { ...pda, sd_enabled: false }, bundle())).toThrow(SdSdkError);
    expect(() => verifyBindingMode({ ...escrow, commit_AAD: { sdMerkleRoot: ZERO_HEX_32 } }, { ...pda, ingestion_mode: "MODE_B" }, bundle())).toThrow(SdSdkError);
    expect(() => assertClaimNotExpired(1, now)).toThrow(SdSdkError);
    expect(() => assertClaimNotExpired(-1, now)).toThrow(SdSdkError);
    expect(() => assertPublicInputsMatch(["1"], ["2"])).toThrow(SdSdkError);
    await expect(verifyClaim({
      sdBundle: bundle(),
      claimItem: bundle().claims[0]!,
      escrowCommit: escrow,
      pdaSdConfig: pda,
      verifierRegistry,
      revocationRegistry: new InMemoryRevocationRegistryClient([disclosureId]),
      now,
    })).rejects.toMatchObject({ code: SdSdkErrorCode.CLAIM_REVOKED });
    await expect(verifyClaim({
      sdBundle: bundle(),
      claimItem: bundle().claims[0]!,
      escrowCommit: escrow,
      pdaSdConfig: pda,
      verifierRegistry: { getVerifierAt: () => null },
      revocationRegistry: new InMemoryRevocationRegistryClient(),
      now,
    })).rejects.toMatchObject({ code: SdSdkErrorCode.PROOF_INVALID });
    await expect(verifyCleartextField({
      sdBundle: bundle(),
      cleartextItem: { ...bundle().cleartext[0]!, value: -1 },
      escrowCommit: escrow,
      pdaSdConfig: pda,
      verifierRegistry,
    })).rejects.toMatchObject({ code: SdSdkErrorCode.FIELD_ENCODING_INVALID });
    await expect(verifyCleartextField({
      sdBundle: bundle(),
      cleartextItem: { ...bundle().cleartext[0]!, opening_proof: undefined },
      escrowCommit: escrow,
      pdaSdConfig: pda,
      verifierRegistry,
    })).rejects.toMatchObject({ code: SdSdkErrorCode.PROOF_INVALID });
    await expect(verifyCleartextField({
      sdBundle: bundle(),
      cleartextItem: { ...bundle().cleartext[0]!, field_id: h(99) },
      escrowCommit: escrow,
      pdaSdConfig: pda,
      verifierRegistry,
    })).rejects.toMatchObject({ code: SdSdkErrorCode.FIELD_POLICY_UNKNOWN });
    await expect(verifyCleartextField({
      sdBundle: { ...bundle(), partner_id: h(99) },
      cleartextItem: bundle().cleartext[0]!,
      escrowCommit: escrow,
      pdaSdConfig: pda,
      verifierRegistry,
    })).rejects.toMatchObject({ code: SdSdkErrorCode.PARTNER_MISMATCH });
  });

  it("covers merkle helper and attested cleartext paths", async () => {
    expect(verifyMerklePath({ fieldCommitment: root, merklePath: [], expectedRoot: root })).toBe(true);
    expect(verifyMerklePath({ fieldCommitment: root, merklePath: [{ sibling: h(55), direction: 0 }], expectedRoot: root })).toBe(false);
    expect(() => normalizeScalarHex("0x12")).toThrow(SdSdkError);
    await expect(verifyCleartextField({
      sdBundle: bundle(),
      cleartextItem: {
        ...bundle().cleartext[0]!,
        opening_mode: "cleartext_attested",
        opening_proof: undefined,
        cleartext_attestation_digest: h(77),
      },
      escrowCommit: escrow,
      pdaSdConfig: pda,
      verifierRegistry,
    })).resolves.toBeUndefined();
  });

  it("recomputes fallback public inputs and rejects bad verifier schema", async () => {
    const noExpected = { ...pda, claims: [{ claim_id: claimId, claim_type: "range" as const, field_ids: [h(5)] }] };
    const claim = {
      ...bundle().claims[0]!,
      proof_context_digest: h(66),
      public_inputs: recomputePublicInputs({
        claimConfig: noExpected.claims[0]!,
        sdBundle: bundle(),
        escrowCommit: escrow,
        claimItem: { ...bundle().claims[0]!, proof_context_digest: h(66) },
      }),
    };
    expect(claim.public_inputs).toHaveLength(14);
    await expect(verifyClaim({
      sdBundle: bundle(),
      claimItem: claim,
      escrowCommit: escrow,
      pdaSdConfig: { ...noExpected, claims: [{ ...noExpected.claims[0]!, public_input_schema_digest: h(44) }] },
      verifierRegistry: { getVerifierAt: () => ({ publicInputSchemaDigest: h(45), verifyProof: () => true }) },
      revocationRegistry: new InMemoryRevocationRegistryClient(),
      now,
    })).rejects.toMatchObject({ code: SdSdkErrorCode.PROOF_INVALID });
    await expect(verifyClaim({
      sdBundle: bundle(),
      claimItem: claim,
      escrowCommit: escrow,
      pdaSdConfig: noExpected,
      verifierRegistry: { getVerifierAt: () => ({ verifyProof: () => false }) },
      revocationRegistry: new InMemoryRevocationRegistryClient(),
      now,
    })).rejects.toMatchObject({ code: SdSdkErrorCode.PROOF_INVALID });
  });
});
