import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Hex32 } from "@cealis/v3-crypto";
import { createLitAdapter, LitChipotleClient } from "../../src/g2-lit/index.js";
import { canonicalizeAcc, hexToBytes, type JsonValue } from "../../src/g2-lit/acc-canonicalize.js";
import { computeLitKemBindingTupleDigest, buildLitKemBindingTuple } from "../../src/g2-lit/kem-binding-proof.js";
import { SigmaBuffer } from "../../src/redaction/sigma-buffer.js";
import { GateKind, type GateRecipientPubkeyEntry } from "../../src/types/gate-recipient.js";
import type { LitAssignmentRecord } from "../../src/types/registries.js";
import type { LitChipotleTransport } from "../../src/g2-lit/chipotle-client.js";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "vendor", "lit");
const sigma = readJson("sigma-vector.json") as { authorizationId: Hex32; h_commit: Hex32; block_hash: Hex32; pubkey: string; signature: string };
const acc = readJson("acc-fixture.json") as JsonValue;
const baseQuote = readJson("dcap-fixture.json") as Record<string, unknown>;
const baseAssignment = readJson("assignment-fixture.json") as { assignedTeeId: Hex32; assignmentBlock: string; assignedTeePubkey: string; sourceGovernanceDigest: Hex32 };

function readJson(name: string): unknown {
  return JSON.parse(readFileSync(join(fixtureDir, name), "utf8")) as unknown;
}

function assignment(): LitAssignmentRecord {
  return {
    authorizationId: sigma.authorizationId,
    assignedTeeId: baseAssignment.assignedTeeId,
    assignmentBlock: BigInt(baseAssignment.assignmentBlock),
    assignedTeePubkey: hexToBytes(baseAssignment.assignedTeePubkey),
    sourceGovernanceDigest: baseAssignment.sourceGovernanceDigest,
  };
}

function kemEntry(): GateRecipientPubkeyEntry {
  return {
    authorizationId: sigma.authorizationId,
    gateKind: GateKind.LitV3,
    conditionalRecipientIndex: 0,
    kemPubkey: new Uint8Array(Array.from({ length: 64 }, (_, i) => i + 1)),
    attestationRef: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    effectiveBlock: 12_000n,
    tombstoneBlock: 0n,
    perCommitEphemeral: true,
  };
}

function quoteWithProof(): Record<string, unknown> {
  const digest = computeLitKemBindingTupleDigest(
    buildLitKemBindingTuple({
      authorizationId: sigma.authorizationId,
      hCommit: sigma.h_commit,
      blockHash: sigma.block_hash,
      kemPubkeyEntry: kemEntry(),
      assignment: assignment(),
      accessStructureProfile: "FIXED_ONLY",
    }),
  );
  return { ...baseQuote, bindingStatementDigests: [digest] };
}

class RegistryReader {
  async getLitAssignmentAt(_authorizationId: Hex32, _blockNumber: bigint): Promise<LitAssignmentRecord | null> {
    return assignment();
  }

  async getGateRecipientPubkeyAt(
    _authorizationId: Hex32,
    _gateKind: GateKind,
    _conditionalRecipientIndex: number,
    _blockNumber: bigint,
  ): Promise<GateRecipientPubkeyEntry | null> {
    return kemEntry();
  }
}

describe("G2 Lit integration happy path", () => {
  it("verifies assignment, quote, sigma, KEM binding proof, and split commit/authorization blocks", async () => {
    const quote = quoteWithProof();
    const proof = { method: "tee-local-statement" as const, tupleDigest: (quote.bindingStatementDigests as Hex32[])[0]! };
    const transport: LitChipotleTransport = {
      async requestSignature() {
        return {
          sigma: sigma.signature,
          dcapQuote: quote,
          assignmentId: baseAssignment.assignedTeeId,
          observedCertificateSha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          apiVersion: "chipotle-core-rest-v1-fixture",
        };
      },
    };
    const adapter = createLitAdapter({
      client: new LitChipotleClient({
        baseUrl: "https://chipotle.lit.mock",
        apiVersion: "chipotle-core-rest-v1-fixture",
        certificatePinSha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        transport,
      }),
    });
    const registryReader = new RegistryReader();
    const binding = await adapter.prepareCommitBinding({
      authorizationId: sigma.authorizationId,
      hCommit: sigma.h_commit,
      commitBlock: 12_000n,
      extras: { registryReader },
    });
    expect(binding.commitBlock).toBe(12_000n);

    const requested = await adapter.requestSigma({
      authorizationId: sigma.authorizationId,
      hCommit: sigma.h_commit,
      authorizationBlock: 12_345n,
      blockHash: sigma.block_hash,
      extras: {
        registryReader,
        commitBlock: 12_000n,
        canonicalAccBytes: canonicalizeAcc(acc),
        dcapQuote: new SigmaBuffer(new TextEncoder().encode(JSON.stringify(quote))),
        accessStructureProfile: "FIXED_ONLY",
        kemBindingProof: proof,
        nowMs: 1_800_000_060_000,
      },
    });
    const result = await adapter.verifySigma({
      authorizationId: sigma.authorizationId,
      hCommit: sigma.h_commit,
      authorizationBlock: 12_345n,
      blockHash: sigma.block_hash,
      sigma: requested.sigma,
      extras: {
        registryReader,
        commitBlock: 12_000n,
        canonicalAccBytes: canonicalizeAcc(acc),
        dcapQuote: requested.dcapQuote,
        accessStructureProfile: "FIXED_ONLY",
        kemBindingProof: proof,
        nowMs: 1_800_000_060_000,
      },
    });
    expect(result).toEqual({ ok: true });
    expect(requested.sigma.length).toBe(96);
  });
});
