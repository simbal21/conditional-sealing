import { createPublicClient, http, type Chain, type PublicClient } from "viem";
import type { Hex32 } from "../types.js";

export interface PartnerRpcClientInput {
  readonly chainRpcUrl: string;
  readonly chainId?: number;
  readonly name?: string;
}

export interface VerifyRevealAuthorizedReceiptInput extends PartnerRpcClientInput {
  readonly txHash: Hex32;
  readonly expectedBlockHash: Hex32;
  readonly expectedLogIndex: number;
}

export type OnlineReceiptVerification =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

export function createPartnerRpcClient(input: PartnerRpcClientInput): PublicClient {
  if (input.chainRpcUrl.trim().length === 0) {
    throw new Error("chainRpcUrl is required for partner RPC reads.");
  }
  const chain = {
    id: input.chainId ?? 8453,
    name: input.name ?? "partner-supplied-chain",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: {
      default: { http: [input.chainRpcUrl] },
    },
  } satisfies Chain;
  return createPublicClient({
    chain,
    transport: http(input.chainRpcUrl),
  });
}

export async function verifyRevealAuthorizedReceipt(
  input: VerifyRevealAuthorizedReceiptInput,
): Promise<OnlineReceiptVerification> {
  const client = createPartnerRpcClient(input);
  const receipt = await client.getTransactionReceipt({ hash: input.txHash });
  if (receipt.blockHash.toLowerCase() !== input.expectedBlockHash.toLowerCase()) {
    return { ok: false, reason: "Receipt blockHash does not match bundle proof." };
  }
  const hasLog = receipt.logs.some((log) => log.logIndex === input.expectedLogIndex);
  if (!hasLog) {
    return { ok: false, reason: "Receipt does not contain expected RevealAuthorized log index." };
  }
  return { ok: true };
}
