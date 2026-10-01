/**
 * M3 custody imports — G4 authority interface types. M7 reads G4 authority
 * entries through M3's typed custody adapter to enforce phase-aware
 * verification per S2-3 §7.
 *
 * Phase A locks the surface contract; Phase B/C/D wire real adapter calls.
 */
import type { Hex } from "viem";

/**
 * G4 authority record per M3 + S2-2 §9.6 + S2-6 §3-§4. Phase 1 ships
 * binary-hash + sealed-code server reference; Phase 2 ships TEE measurement
 * + DCAP verifier ref.
 */
export interface G4AuthorityRecord {
  readonly entryRef: Hex; // g4_authority_ref
  readonly phase: 1 | 2;
  readonly binaryHash: Hex; // Phase 1
  readonly teeMeasurement: Hex | null; // Phase 2
  readonly authorityPubkey: Hex;
  readonly dcapVerifierRef: Hex | null; // Phase 2
  readonly vendorFamily: string | null; // Phase 2 (cross-vendor disjointness)
  readonly metadataHash: Hex;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
  readonly deprecationFlagSet: boolean;
}

/**
 * Phase 2 DCAP acceptance packet per S2-6 §4.2.1 lines 199–205.
 */
export interface DcapAcceptancePacket {
  readonly g4AuthorityRef: Hex;
  readonly phase: 2;
  readonly authorityPubkey: Hex;
  readonly teeMeasurement: Hex;
  readonly dcapVerifierRef: Hex;
  readonly effectiveBlock: bigint;
  readonly metadataHash: Hex;
  readonly admissionAuthoritativeMode: "snark-backed" | "on-chain-verifier";
  readonly acceptedTcbStatuses: readonly string[];
  readonly vendorFamilyClassification: string; // throws on ambiguous
  readonly litG4DisjointnessVerified: boolean;
  readonly collateralFreshnessUnix: number;
  readonly quoteProofDigest: Hex;
  readonly userDataDigest: Hex;
}
