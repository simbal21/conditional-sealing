// Trimmed ABI for `G4RefusalRegistry`. Source: M2 ABI JSON.
//
// `refusalState(authorizationId)` returns `(refused, reasonCode, encrypted)`.
// For at-block reads the V3 SDK passes `blockNumber` to `viem.readContract`
// — the chain handles the at-block semantics natively for view functions.

export const g4RefusalRegistryAbi = [
  {
    type: "function",
    name: "refusalState",
    inputs: [{ name: "authorizationId", type: "bytes32", internalType: "bytes32" }],
    outputs: [
      { name: "refused", type: "bool", internalType: "bool" },
      { name: "reasonCode", type: "uint8", internalType: "uint8" },
      { name: "encrypted", type: "bool", internalType: "bool" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "signalState",
    inputs: [{ name: "authorizationId", type: "bytes32", internalType: "bytes32" }],
    outputs: [
      { name: "signaled", type: "bool", internalType: "bool" },
      { name: "reasonCode", type: "uint8", internalType: "uint8" },
    ],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "RefusalSignal",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: false },
      { name: "hCommit", type: "bytes32", indexed: false },
      { name: "reasonCode", type: "uint8", indexed: false },
      { name: "blocking", type: "bool", indexed: false },
    ],
  },
  {
    type: "event",
    name: "AdvisorySignal",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: false },
      { name: "hCommit", type: "bytes32", indexed: false },
      { name: "reasonCode", type: "uint8", indexed: false },
    ],
  },
  {
    type: "event",
    name: "RefusalReasonEncrypted",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: false },
      { name: "encryptedReasonBlob", type: "bytes", indexed: false },
    ],
  },
  {
    type: "event",
    name: "RefusalReasonPublic",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: false },
      { name: "reasonCode", type: "uint8", indexed: false },
      { name: "proofRef", type: "bytes32", indexed: false },
    ],
  },
] as const;
