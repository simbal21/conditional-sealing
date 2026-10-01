import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Hex32 } from "@cealis/v3-crypto";
import { CUSTODY_ERROR_CODES } from "../../src/errors.js";
import { hexToBytes } from "../../src/g2-lit/acc-canonicalize.js";
import { verifyLitDcapQuote } from "../../src/g2-lit/dcap-verify.js";
import { buildLitKemBindingTuple, computeLitKemBindingTupleDigest, verifyLitKemBindingProof } from "../../src/g2-lit/kem-binding-proof.js";
import { GateKind, type GateRecipientPubkeyEntry } from "../../src/types/gate-recipient.js";
import type { LitAssignmentRecord } from "../../src/types/registries.js";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "vendor", "lit");
const sigma = JSON.parse(readFileSync(join(fixtureDir, "sigma-vector.json"), "utf8")) as { authorizationId: Hex32; h_commit: Hex32; block_hash: Hex32 };
const assignmentFixture = JSON.parse(readFileSync(join(fixtureDir, "assignment-fixture.json"), "utf8")) as { assignedTeeId: Hex32; assignmentBlock: string; assignedTeePubkey: string; sourceGovernanceDigest: Hex32 };
const quoteFixture = JSON.parse(readFileSync(join(fixtureDir, "dcap-fixture.json"), "utf8")) as Record<string, unknown>;

function assignment(): LitAssignmentRecord {
  return {
    authorizationId: sigma.authorizationId,
    assignedTeeId: assignmentFixture.assignedTeeId,
    assignmentBlock: BigInt(assignmentFixture.assignmentBlock),
    assignedTeePubkey: hexToBytes(assignmentFixture.assignedTeePubkey),
    sourceGovernanceDigest: assignmentFixture.sourceGovernanceDigest,
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

describe("G2 Lit KEM binding proof", () => {
  it("rejects a valid sigma context when the KEM-to-assignment proof is missing or absent from quote evidence", () => {
    const tupleDigest = computeLitKemBindingTupleDigest(
      buildLitKemBindingTuple({
        authorizationId: sigma.authorizationId,
        hCommit: sigma.h_commit,
        blockHash: sigma.block_hash,
        kemPubkeyEntry: kemEntry(),
        assignment: assignment(),
        accessStructureProfile: "FIXED_ONLY",
      }),
    );
    const quote = verifyLitDcapQuote({
      quote: quoteFixture,
      authorizationId: sigma.authorizationId,
      hCommit: sigma.h_commit,
      blockHash: sigma.block_hash,
      nowMs: 1_800_000_060_000,
    });
    expect(() =>
      verifyLitKemBindingProof({
        authorizationId: sigma.authorizationId,
        hCommit: sigma.h_commit,
        blockHash: sigma.block_hash,
        kemPubkeyEntry: kemEntry(),
        assignment: assignment(),
        accessStructureProfile: "FIXED_ONLY",
        proof: null,
        verifiedQuote: quote,
      }),
    ).toThrow(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);
    expect(() =>
      verifyLitKemBindingProof({
        authorizationId: sigma.authorizationId,
        hCommit: sigma.h_commit,
        blockHash: sigma.block_hash,
        kemPubkeyEntry: kemEntry(),
        assignment: assignment(),
        accessStructureProfile: "FIXED_ONLY",
        proof: { method: "tee-local-statement", tupleDigest },
        verifiedQuote: quote,
      }),
    ).toThrow(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);
  });
});
