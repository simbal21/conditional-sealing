import type { Hex32 } from "@cealis/v3-crypto";
import type { Address } from "../chain/types.js";
import { canonicalizeAcc, type JsonValue } from "./acc-canonicalize.js";

export interface LitAccBindingInput {
  readonly chainId: number;
  readonly conditionEngineAddress: Address;
  readonly attestationGateAddress: Address;
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly revealAuthorizedBlockHash: Hex32;
  readonly canGatesSign: boolean;
  readonly noCurrentShredState: boolean;
}

export interface LitAccBinding {
  readonly acc: JsonValue;
  readonly canonicalBytes: Uint8Array;
}

export function buildLitAccBinding(input: LitAccBindingInput): LitAccBinding {
  if (input.chainId !== 8453 && input.chainId !== 84532 && input.chainId !== 31337) {
    throw new Error(`unsupported ACC chainId ${input.chainId}`);
  }
  if (!input.canGatesSign) {
    throw new Error("Lit ACC cannot be built when canGatesSign is false");
  }
  if (!input.noCurrentShredState) {
    throw new Error("Lit ACC cannot be built while current shred state blocks signing");
  }

  const acc: JsonValue = {
    protocol: "cealis-v3-lit-acc",
    version: 1,
    chain: {
      chainId: input.chainId,
      family: "base",
    },
    contracts: {
      attestationGate: input.attestationGateAddress.toLowerCase(),
      conditionEngine: input.conditionEngineAddress.toLowerCase(),
    },
    reveal: {
      authorizationId: input.authorizationId.toLowerCase(),
      h_commit: input.hCommit.toLowerCase(),
      revealAuthorizedBlockHash: input.revealAuthorizedBlockHash.toLowerCase(),
      finalized: true,
    },
    predicates: [
      {
        kind: "evm-call",
        contractAddress: input.attestationGateAddress.toLowerCase(),
        functionSignature: "canGatesSign(bytes32)",
        args: [input.authorizationId.toLowerCase()],
        returnValueTest: {
          comparator: "=",
          value: true,
        },
      },
      {
        kind: "current-state",
        contractAddress: input.conditionEngineAddress.toLowerCase(),
        functionSignature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
        args: [input.authorizationId.toLowerCase(), input.hCommit.toLowerCase()],
        blockHash: input.revealAuthorizedBlockHash.toLowerCase(),
      },
      {
        kind: "current-shred-state",
        h_commit: input.hCommit.toLowerCase(),
        mustBeSignable: true,
      },
    ],
  };

  return {
    acc,
    canonicalBytes: canonicalizeAcc(acc),
  };
}
