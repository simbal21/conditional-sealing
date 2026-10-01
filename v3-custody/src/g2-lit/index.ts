import type { Hex32 } from "@cealis/v3-crypto";
import type {
  GateAdapter,
  HealthProbeResult,
  PrepareCommitBindingInput,
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "../adapters/gate-adapter.js";
import { GateKind, type GateRecipientPubkeyEntry } from "../types/gate-recipient.js";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";
import type { SigmaBuffer } from "../redaction/sigma-buffer.js";
import type { LitAssignmentReader } from "./assignment-fetch.js";
import { fetchAndVerifyLitAssignment } from "./assignment-fetch.js";
import type { LitChipotleClient } from "./chipotle-client.js";
import { buildLitIdempotencyKey } from "./chipotle-client.js";
import { verifyLitDcapQuote, type LitDcapVerification } from "./dcap-verify.js";
import { verifyLitKemBindingProof, computeLitKemPubkeyDigest, type LitKemBindingProof } from "./kem-binding-proof.js";
import { verifyLitSigma } from "./sigma-verify.js";
import { litHealthProbe } from "./health-probe.js";
import { assertVendorFamiliesDisjoint, type VendorFamilyResult } from "./vendor-family-normalize.js";

export { buildLitAccBinding } from "./acc-binding.js";
export { canonicalizeAcc, canonicalizeAccString } from "./acc-canonicalize.js";
export { fetchAndVerifyLitAssignment } from "./assignment-fetch.js";
export { LitChipotleClient, assertChipotleEvidenceSurface, buildLitIdempotencyKey } from "./chipotle-client.js";
export { parseLitDcapQuote, litDcapQuoteDigest } from "./dcap-quote.js";
export { verifyLitDcapQuote, computeLitUserData, computeLitUserDataDigest } from "./dcap-verify.js";
export { computeLitAccBindingDigest, verifyLitSigma } from "./sigma-verify.js";
export { computeLitKemPubkeyDigest, computeLitKemBindingTupleDigest, verifyLitKemBindingProof } from "./kem-binding-proof.js";
export { normalizeVendorFamily, assertVendorFamiliesDisjoint } from "./vendor-family-normalize.js";
export { verifyLitChannelIdentity } from "./channel-identity.js";
export { litHealthProbe } from "./health-probe.js";

export interface LitKemPubkey {
  readonly entry: GateRecipientPubkeyEntry;
  readonly litKemPubkeyDigest: Hex32;
  readonly commitBlock: bigint;
}

export interface LitPrepareExtras {
  readonly registryReader: LitGateRecipientReader;
}

export interface LitRequestExtras {
  readonly registryReader: LitAssignmentReader & LitGateRecipientReader;
  readonly commitBlock: bigint;
  readonly canonicalAccBytes: Uint8Array;
  readonly dcapQuote: SigmaBuffer;
  readonly accessStructureProfile: string;
  readonly kemBindingProof: LitKemBindingProof | null;
  readonly expectedSourceGovernanceDigest?: Hex32;
  readonly g4VendorFamily?: VendorFamilyResult;
  readonly nowMs?: number;
}

export interface LitGateRecipientReader {
  getGateRecipientPubkeyAt(
    authorizationId: Hex32,
    gateKind: GateKind,
    conditionalRecipientIndex: number,
    blockNumber: bigint,
  ): Promise<GateRecipientPubkeyEntry | null>;
}

export interface LitAdapterConfig {
  readonly client: LitChipotleClient;
}

export type SigmaLit = Uint8Array;

export interface LitRequestSigmaResult extends RequestSigmaResult {
  readonly sigma: Uint8Array;
  readonly dcapQuote: SigmaBuffer;
}

export function createLitAdapter(config: LitAdapterConfig): LitAdapter {
  return new LitAdapter(config);
}

export class LitAdapter implements GateAdapter<SigmaLit, LitKemPubkey, LitRequestExtras, LitPrepareExtras> {
  public readonly gateKind = GateKind.LitV3;
  private readonly client: LitChipotleClient;

  constructor(config: LitAdapterConfig) {
    this.client = config.client;
  }

  public async prepareCommitBinding(
    input: PrepareCommitBindingInput<LitPrepareExtras>,
  ): Promise<LitKemPubkey> {
    const entry = await input.extras.registryReader.getGateRecipientPubkeyAt(
      input.authorizationId,
      GateKind.LitV3,
      0,
      input.commitBlock,
    );
    if (entry === null) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL,
        "Lit KEM pubkey missing at commit block",
      );
    }
    if (entry.gateKind !== GateKind.LitV3 || entry.conditionalRecipientIndex !== 0) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
        "Lit KEM pubkey registry entry is not the top-level Lit stanza",
      );
    }
    if (!entry.perCommitEphemeral) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
        "Lit KEM pubkey must be per-commit ephemeral",
      );
    }
    return {
      entry,
      litKemPubkeyDigest: computeLitKemPubkeyDigest(entry.kemPubkey),
      commitBlock: input.commitBlock,
    };
  }

  public async requestSigma(
    input: RequestSigmaInput<LitRequestExtras>,
  ): Promise<LitRequestSigmaResult> {
    const quote = verifyLitDcapQuote({
      quote: input.extras.dcapQuote,
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      blockHash: input.blockHash,
      nowMs: input.extras.nowMs,
    });
    const idempotencyKey = buildLitIdempotencyKey({
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      authorizationBlock: input.authorizationBlock,
      assignedTeeId: quote.assignedTeeId,
    });
    const response = await this.client.requestSigma({
      canonicalAccBytes: input.extras.canonicalAccBytes,
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      blockHash: input.blockHash,
      idempotencyKey,
    });
    const sigmaBytes = response.sigma.unwrap();
    response.sigma.zeroize();
    return {
      sigma: sigmaBytes,
      dcapQuote: response.dcapQuote,
      gateKind: GateKind.LitV3,
      metadata: {
        assignmentId: response.assignmentId,
        quoteDigest: response.quoteDigest as Hex32,
        receivedAt: response.receivedAt,
      },
    };
  }

  public async verifySigma(
    input: RequestSigmaInput<LitRequestExtras> & { sigma: Uint8Array },
  ): Promise<VerifySigmaResult> {
    try {
      const quote = verifyLitDcapQuote({
        quote: input.extras.dcapQuote,
        authorizationId: input.authorizationId,
        hCommit: input.hCommit,
        blockHash: input.blockHash,
        nowMs: input.extras.nowMs,
      });
      if (input.extras.g4VendorFamily !== undefined) {
        assertVendorFamiliesDisjoint(quote.vendorFamily, input.extras.g4VendorFamily);
      }
      const assignment = await fetchAndVerifyLitAssignment({
        registryReader: input.extras.registryReader,
        authorizationId: input.authorizationId,
        authorizationBlock: input.authorizationBlock,
        assignedTeeIdFromQuote: quote.assignedTeeId,
        expectedSourceGovernanceDigest: input.extras.expectedSourceGovernanceDigest,
      });
      const sigmaResult = verifyLitSigma({
        authorizationId: input.authorizationId,
        hCommit: input.hCommit,
        blockHash: input.blockHash,
        sigma: input.sigma,
        assignedTeePubkey: assignment.assignment.assignedTeePubkey,
        canonicalAccBytes: input.extras.canonicalAccBytes,
      });
      if (!sigmaResult.ok) return sigmaResult;

      const kemEntry = await input.extras.registryReader.getGateRecipientPubkeyAt(
        input.authorizationId,
        GateKind.LitV3,
        0,
        input.extras.commitBlock,
      );
      if (kemEntry === null) {
        return { ok: false, code: CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL };
      }
      verifyLitKemBindingProof({
        authorizationId: input.authorizationId,
        hCommit: input.hCommit,
        blockHash: input.blockHash,
        kemPubkeyEntry: kemEntry,
        assignment: assignment.assignment,
        accessStructureProfile: input.extras.accessStructureProfile,
        proof: input.extras.kemBindingProof,
        verifiedQuote: quote,
      });
      return { ok: true };
    } catch (err) {
      if (err instanceof CustodyError) {
        return { ok: false, code: err.code, detail: err.subCodes[0] };
      }
      return { ok: false, code: CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE };
    }
  }

  public async healthProbe(): Promise<HealthProbeResult> {
    return litHealthProbe({ client: this.client });
  }
}

export type { LitDcapVerification };
