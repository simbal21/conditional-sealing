import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Hex32 } from "@cealis/v3-crypto";
import { CUSTODY_ERROR_CODES, CustodyError } from "../../errors.js";
import { SigmaBuffer } from "../../redaction/sigma-buffer.js";
import { safeStringify } from "../../redaction/log-sanitize.js";
import { GateKind, type GateRecipientPubkeyEntry } from "../../types/gate-recipient.js";
import type { LitAssignmentRecord } from "../../types/registries.js";
import { canonicalizeAcc, canonicalizeAccString, hexToBytes, type JsonValue } from "../acc-canonicalize.js";
import { buildLitAccBinding } from "../acc-binding.js";
import { fetchAndVerifyLitAssignment, type LitAssignmentReader } from "../assignment-fetch.js";
import {
  LitChipotleClient,
  assertChipotleEvidenceSurface,
  buildLitIdempotencyKey,
  type LitChipotleTransport,
} from "../chipotle-client.js";
import { verifyLitDcapQuote } from "../dcap-verify.js";
import {
  buildLitKemBindingTuple,
  computeLitKemBindingTupleDigest,
  verifyLitKemBindingProof,
} from "../kem-binding-proof.js";
import { verifyLitSigma } from "../sigma-verify.js";
import {
  assertVendorFamiliesDisjoint,
  normalizeVendorFamily,
} from "../vendor-family-normalize.js";

const fixtureDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "tests",
  "fixtures",
  "vendor",
  "lit",
);

const sigmaVector = readJson("sigma-vector.json") as {
  authorizationId: Hex32;
  h_commit: Hex32;
  block_hash: Hex32;
  pubkey: string;
  signature: string;
};
const assignmentFixture = readJson("assignment-fixture.json") as {
  authorizationId: Hex32;
  assignedTeeId: Hex32;
  assignmentBlock: string;
  assignedTeePubkey: string;
  sourceGovernanceDigest: Hex32;
};
const dcapFixture = readJson("dcap-fixture.json") as Record<string, unknown>;
const accFixture = readJson("acc-fixture.json") as JsonValue;

function readJson(name: string): unknown {
  return JSON.parse(readFileSync(join(fixtureDir, name), "utf8")) as unknown;
}

function assignment(): LitAssignmentRecord {
  return {
    authorizationId: assignmentFixture.authorizationId,
    assignedTeeId: assignmentFixture.assignedTeeId,
    assignmentBlock: BigInt(assignmentFixture.assignmentBlock),
    assignedTeePubkey: hexToBytes(assignmentFixture.assignedTeePubkey),
    sourceGovernanceDigest: assignmentFixture.sourceGovernanceDigest,
  };
}

function kemEntry(): GateRecipientPubkeyEntry {
  return {
    authorizationId: sigmaVector.authorizationId,
    gateKind: GateKind.LitV3,
    conditionalRecipientIndex: 0,
    kemPubkey: new Uint8Array(Array.from({ length: 64 }, (_, i) => i + 1)),
    attestationRef: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    effectiveBlock: 12_000n,
    tombstoneBlock: 0n,
    perCommitEphemeral: true,
  };
}

function quoteWithBinding(): Record<string, unknown> {
  const tuple = buildLitKemBindingTuple({
    authorizationId: sigmaVector.authorizationId,
    hCommit: sigmaVector.h_commit,
    blockHash: sigmaVector.block_hash,
    kemPubkeyEntry: kemEntry(),
    assignment: assignment(),
    accessStructureProfile: "FIXED_ONLY",
  });
  const tupleDigest = computeLitKemBindingTupleDigest(tuple);
  return {
    ...dcapFixture,
    bindingStatementDigests: [tupleDigest],
  };
}

class AssignmentReader implements LitAssignmentReader {
  public record: LitAssignmentRecord | null = assignment();

  async getLitAssignmentAt(_authorizationId: Hex32, _blockNumber: bigint): Promise<LitAssignmentRecord | null> {
    return this.record;
  }
}

describe("G2 Lit unit surface", () => {
  it("canonicalizes semantically equivalent ACC JSON byte-identically", () => {
    const one = canonicalizeAcc(accFixture);
    const two = canonicalizeAcc({
      predicates: (accFixture as { predicates: JsonValue }).predicates,
      reveal: (accFixture as { reveal: JsonValue }).reveal,
      contracts: (accFixture as { contracts: JsonValue }).contracts,
      chain: (accFixture as { chain: JsonValue }).chain,
      version: 1,
      protocol: "cealis-v3-lit-acc",
    });
    expect(two).toEqual(one);
    expect(canonicalizeAccString(accFixture)).not.toContain(" ");
  });

  it("constructs the canonical ACC request with explicit chain, contracts, function signatures, and shred predicate", () => {
    const built = buildLitAccBinding({
      chainId: 84532,
      conditionEngineAddress: "0x1111111111111111111111111111111111111111",
      attestationGateAddress: "0x2222222222222222222222222222222222222222",
      authorizationId: sigmaVector.authorizationId,
      hCommit: sigmaVector.h_commit,
      revealAuthorizedBlockHash: sigmaVector.block_hash,
      canGatesSign: true,
      noCurrentShredState: true,
    });
    expect(canonicalizeAccString(built.acc)).toBe(canonicalizeAccString(accFixture));
  });

  it("derives the S2-3 Lit idempotency key", () => {
    expect(
      buildLitIdempotencyKey({
        authorizationId: sigmaVector.authorizationId,
        hCommit: sigmaVector.h_commit,
        authorizationBlock: 12_345n,
        assignedTeeId: assignmentFixture.assignedTeeId,
      }),
    ).toBe(`${sigmaVector.authorizationId}:${sigmaVector.h_commit}:12345:${assignmentFixture.assignedTeeId}`);
  });

  it("verifies quote, assignment, sigma, and KEM binding proof on the happy path", async () => {
    const quote = verifyLitDcapQuote({
      quote: quoteWithBinding(),
      authorizationId: sigmaVector.authorizationId,
      hCommit: sigmaVector.h_commit,
      blockHash: sigmaVector.block_hash,
      nowMs: 1_800_000_060_000,
    });
    const proof = { method: "tee-local-statement" as const, tupleDigest: quote.bindingStatementDigests[0]! };
    const reader = new AssignmentReader();
    const verifiedAssignment = await fetchAndVerifyLitAssignment({
      registryReader: reader,
      authorizationId: sigmaVector.authorizationId,
      authorizationBlock: 12_345n,
      assignedTeeIdFromQuote: quote.assignedTeeId,
    });
    const sigma = new SigmaBuffer(hexToBytes(sigmaVector.signature));
    expect(
      verifyLitSigma({
        authorizationId: sigmaVector.authorizationId,
        hCommit: sigmaVector.h_commit,
        blockHash: sigmaVector.block_hash,
        sigma,
        assignedTeePubkey: verifiedAssignment.assignment.assignedTeePubkey,
        canonicalAccBytes: canonicalizeAcc(accFixture),
      }),
    ).toEqual({ ok: true });
    expect(() => sigma.unwrap()).toThrow(/zeroized/);
    expect(() =>
      verifyLitKemBindingProof({
        authorizationId: sigmaVector.authorizationId,
        hCommit: sigmaVector.h_commit,
        blockHash: sigmaVector.block_hash,
        kemPubkeyEntry: kemEntry(),
        assignment: verifiedAssignment.assignment,
        accessStructureProfile: "FIXED_ONLY",
        proof,
        verifiedQuote: quote,
      }),
    ).not.toThrow();
  });

  it("maps every S2-3 §3.6 failure class to the required CUSTODY_ERR code", async () => {
    const transport: LitChipotleTransport = {
      async requestSignature() {
        throw new Error("down");
      },
    };
    const client = new LitChipotleClient({
      baseUrl: "https://chipotle.lit.mock",
      apiVersion: "chipotle-core-rest-v1-fixture",
      certificatePinSha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      transport,
    });
    await expect(
      client.requestSigma({
        canonicalAccBytes: canonicalizeAcc(accFixture),
        authorizationId: sigmaVector.authorizationId,
        hCommit: sigmaVector.h_commit,
        blockHash: sigmaVector.block_hash,
        idempotencyKey: "x",
      }),
    ).rejects.toMatchObject({ code: CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE });

    const reader = new AssignmentReader();
    reader.record = null;
    await expect(
      fetchAndVerifyLitAssignment({
        registryReader: reader,
        authorizationId: sigmaVector.authorizationId,
        authorizationBlock: 12_345n,
        assignedTeeIdFromQuote: assignmentFixture.assignedTeeId,
      }),
    ).rejects.toMatchObject({ code: CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISSING });

    reader.record = { ...assignment(), assignedTeeId: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" };
    await expect(
      fetchAndVerifyLitAssignment({
        registryReader: reader,
        authorizationId: sigmaVector.authorizationId,
        authorizationBlock: 12_345n,
        assignedTeeIdFromQuote: assignmentFixture.assignedTeeId,
      }),
    ).rejects.toMatchObject({ code: CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH });

    expect(() =>
      verifyLitDcapQuote({
        quote: { ...dcapFixture, signatureChainValid: false },
        authorizationId: sigmaVector.authorizationId,
        hCommit: sigmaVector.h_commit,
        blockHash: sigmaVector.block_hash,
        nowMs: 1_800_000_060_000,
      }),
    ).toThrow(CustodyError);

    expect(() =>
      verifyLitDcapQuote({
        quote: { ...dcapFixture, userData: "0x" + "00".repeat(64) },
        authorizationId: sigmaVector.authorizationId,
        hCommit: sigmaVector.h_commit,
        blockHash: sigmaVector.block_hash,
        nowMs: 1_800_000_060_000,
      }),
    ).toThrow(CustodyError);

    const badSig = new Uint8Array(hexToBytes(sigmaVector.signature));
    badSig[0]! ^= 1;
    expect(
      verifyLitSigma({
        authorizationId: sigmaVector.authorizationId,
        hCommit: sigmaVector.h_commit,
        blockHash: sigmaVector.block_hash,
        sigma: badSig,
        assignedTeePubkey: hexToBytes(sigmaVector.pubkey),
        canonicalAccBytes: canonicalizeAcc(accFixture),
      }),
    ).toMatchObject({ ok: false, code: CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_SIG_INVALID });

    const accRejectedClient = new LitChipotleClient({
      baseUrl: "https://chipotle.lit.mock",
      apiVersion: "chipotle-core-rest-v1-fixture",
      certificatePinSha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      transport: {
        async requestSignature() {
          throw new CustodyError(CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ACC_REJECTED, "fixture ACC rejected");
        },
      },
    });
    await expect(
      accRejectedClient.requestSigma({
        canonicalAccBytes: canonicalizeAcc(accFixture),
        authorizationId: sigmaVector.authorizationId,
        hCommit: sigmaVector.h_commit,
        blockHash: sigmaVector.block_hash,
        idempotencyKey: "x",
      }),
    ).rejects.toMatchObject({ code: CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ACC_REJECTED });
  });

  it("redacts sigma and quote-like bytes from logs and JSON", () => {
    const secret = new SigmaBuffer(hexToBytes(sigmaVector.signature));
    const rendered = safeStringify({ sigma: secret, quote: new Uint8Array(96).fill(0xab) });
    expect(rendered).not.toContain(sigmaVector.signature.slice(2, 18));
    expect(rendered).not.toContain("171");
    expect(rendered).toContain("$sigmaBuffer");
  });

  it("normalizes vendor families and fails closed on same or ambiguous families", () => {
    const intelSgx = normalizeVendorFamily({ vendorRoot: "Intel Root", isolationTechnology: "SGX" });
    const intelTdx = normalizeVendorFamily({ vendorRoot: "Intel Root", isolationTechnology: "TDX" });
    const amd = normalizeVendorFamily({ vendorRoot: "AMD", isolationTechnology: "SEV-SNP" });
    const nitro = normalizeVendorFamily({ vendorRoot: "AWS", isolationTechnology: "Nitro" });
    const ambiguous = normalizeVendorFamily({ vendorRoot: "unknown" });
    expect(intelSgx.family).toBe("INTEL");
    expect(intelTdx.family).toBe("INTEL");
    expect(amd.family).toBe("AMD");
    expect(nitro.family).toBe("AWS_NITRO");
    expect(ambiguous.family).toBe("AMBIGUOUS");
    expect(() => assertVendorFamiliesDisjoint(intelSgx, intelTdx)).toThrow(CustodyError);
    expect(() => assertVendorFamiliesDisjoint(ambiguous, amd)).toThrow(CustodyError);
    expect(() => assertVendorFamiliesDisjoint(intelSgx, amd)).not.toThrow();
  });

  it("rejects decrypt-only Lit SDK surfaces", () => {
    expect(() => assertChipotleEvidenceSurface({ decrypt() {} })).toThrow(CustodyError);
    expect(() => assertChipotleEvidenceSurface({ executeJs() {}, decrypt() {} })).not.toThrow();
  });
});
