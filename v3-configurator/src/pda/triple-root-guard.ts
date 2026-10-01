import { bytesEqual, bytesToHex } from "./pda-root.js";

export interface TripleRootCheck {
  readonly local: Uint8Array;
  readonly contractHelper: Uint8Array;
  readonly emittedEvent: Uint8Array;
}

export interface MockPdaRegisteredEvent {
  readonly contractHelper: Uint8Array;
  readonly pdaRoot: Uint8Array;
  readonly txHash: `0x${string}`;
  readonly blockNumber: bigint;
}

export class TerminalEmissionFailure extends Error {
  readonly check: {
    readonly local: `0x${string}`;
    readonly contractHelper: `0x${string}`;
    readonly emittedEvent: `0x${string}`;
  };

  constructor(message: string, check: TripleRootCheck) {
    super(message);
    this.name = "TerminalEmissionFailure";
    this.check = {
      local: bytesToHex(check.local),
      contractHelper: bytesToHex(check.contractHelper),
      emittedEvent: bytesToHex(check.emittedEvent),
    };
  }
}

export function tripleRootGuard(check: TripleRootCheck): void {
  const localMatchesHelper = bytesEqual(check.local, check.contractHelper);
  const helperMatchesEvent = bytesEqual(check.contractHelper, check.emittedEvent);
  if (!localMatchesHelper || !helperMatchesEvent) {
    throw new TerminalEmissionFailure("pda_root triple-comparison failed", check);
  }
}

export async function mockRegisterPDA(pdaRoot: Uint8Array): Promise<MockPdaRegisteredEvent> {
  return {
    contractHelper: new Uint8Array(pdaRoot),
    pdaRoot: new Uint8Array(pdaRoot),
    txHash: `0x${"44".repeat(32)}`,
    blockNumber: 1n,
  };
}
