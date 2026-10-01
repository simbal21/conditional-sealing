import { parseAbiItem, type Address, type Hex, type PublicClient, type WatchEventReturnType } from "viem";

export const SHRED_FINALIZED_EVENT = parseAbiItem(
  "event ShredFinalized(bytes32 indexed authorizationId, bytes32 indexed hCommit, bytes32 proofShred)",
);

export interface ShredFinalizedLog {
  readonly authorizationId: Hex;
  readonly hCommit: Hex;
  readonly proofShred: Hex;
  readonly blockNumber: bigint;
  readonly transactionHash?: Hex;
  readonly logIndex?: number;
}

export interface WatchShredFinalizedOptions {
  readonly publicClient: PublicClient;
  readonly shredRegistryAddress: Address;
  readonly onShredFinalized: (event: ShredFinalizedLog) => void | Promise<void>;
}

export function watchShredFinalized(options: WatchShredFinalizedOptions): WatchEventReturnType {
  return options.publicClient.watchEvent({
    address: options.shredRegistryAddress,
    event: SHRED_FINALIZED_EVENT,
    onLogs: (logs) => {
      for (const log of logs) {
        const args = log.args;
        if (!args.authorizationId || !args.hCommit || !args.proofShred || !log.blockNumber) {
          continue;
        }
        void options.onShredFinalized({
          authorizationId: args.authorizationId,
          hCommit: args.hCommit,
          proofShred: args.proofShred,
          blockNumber: log.blockNumber,
          transactionHash: log.transactionHash,
          logIndex: log.logIndex,
        });
      }
    },
  });
}

