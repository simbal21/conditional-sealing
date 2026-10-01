import { keccak_256 } from "@noble/hashes/sha3";
import type { Hex32 } from "@cealis/v3-crypto";
import type { RefusalState, SignalState } from "../types/refusal.js";
import {
  isEncryptedReasonMode,
  validateAdvisory,
  validateBlocking,
} from "./refusal-runtime-validate.js";

export interface G4RefusalStateReader {
  getRefusalStateAt(authorizationId: Hex32, blockNumber: bigint): Promise<RefusalState>;
  getSignalStateAt(authorizationId: Hex32, blockNumber: bigint): Promise<SignalState>;
}

export interface G4RefusalWriter {
  recordSignal(
    authorizationId: Hex32,
    hCommit: Hex32,
    reasonCode: number,
    blocking: boolean,
    reasonData: Uint8Array,
  ): Promise<Hex32>;
  refusePublic(
    authorizationId: Hex32,
    hCommit: Hex32,
    reasonCode: number,
    proofRef: Hex32,
  ): Promise<Hex32>;
  refuseEncrypted(
    authorizationId: Hex32,
    hCommit: Hex32,
    reasonCode: number,
    encryptedReasonBlob: Uint8Array,
  ): Promise<Hex32>;
  recordAdvisorySignal(
    authorizationId: Hex32,
    hCommit: Hex32,
    reasonCode: number,
  ): Promise<Hex32>;
}

export class G4RefusalRegistrySurface {
  constructor(
    private readonly reader: G4RefusalStateReader,
    private readonly writer?: G4RefusalWriter,
  ) {}

  public getRefusalState(authorizationId: Hex32, blockNumber: bigint): Promise<RefusalState> {
    return this.reader.getRefusalStateAt(authorizationId, blockNumber);
  }

  public getSignalState(authorizationId: Hex32, blockNumber: bigint): Promise<SignalState> {
    return this.reader.getSignalStateAt(authorizationId, blockNumber);
  }

  public async refusePublic(
    authorizationId: Hex32,
    hCommit: Hex32,
    reasonCode: number,
    proofRef: Hex32,
  ): Promise<Hex32> {
    validateBlocking(reasonCode);
    if (isEncryptedReasonMode(reasonCode)) {
      throw new Error("Sensitive G4 refusal codes 0x02/0x03 must use refuseEncrypted");
    }
    return this.requireWriter().refusePublic(authorizationId, hCommit, reasonCode, proofRef);
  }

  public async refuseEncrypted(
    authorizationId: Hex32,
    hCommit: Hex32,
    reasonCode: number,
    encryptedReasonBlob: Uint8Array,
  ): Promise<Hex32> {
    validateBlocking(reasonCode);
    return this.requireWriter().refuseEncrypted(
      authorizationId,
      hCommit,
      reasonCode,
      encryptedReasonBlob,
    );
  }

  public async recordAdvisorySignal(
    authorizationId: Hex32,
    hCommit: Hex32,
    reasonCode: number,
  ): Promise<Hex32> {
    validateAdvisory(reasonCode);
    return this.requireWriter().recordAdvisorySignal(authorizationId, hCommit, reasonCode);
  }

  public async recordSignal(
    authorizationId: Hex32,
    hCommit: Hex32,
    reasonCode: number,
    blocking: boolean,
    reasonData: Uint8Array,
  ): Promise<Hex32> {
    if (blocking) validateBlocking(reasonCode);
    else validateAdvisory(reasonCode);
    return this.requireWriter().recordSignal(authorizationId, hCommit, reasonCode, blocking, reasonData);
  }

  private requireWriter(): G4RefusalWriter {
    if (this.writer === undefined) {
      throw new Error("G4RefusalRegistrySurface writer unavailable in read-only adapter context");
    }
    return this.writer;
  }
}

export function encryptedReasonBlobHash(encryptedReasonBlob: Uint8Array): Hex32 {
  return bytesToHex32(keccak_256(encryptedReasonBlob));
}

function bytesToHex32(bytes: Uint8Array): Hex32 {
  if (bytes.length !== 32) throw new Error(`expected 32 bytes, got ${bytes.length}`);
  let hex = "0x";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex as Hex32;
}
