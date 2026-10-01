// Trimmed ABI for `ShredRegistry`. Source: M2 ABI JSON.
//
// `currentShredState(hCommit)` returns `uint8` (per `ShredState` enum
// in M2 Enums.sol). The SDK uses this for the current-state safety
// read in step 4 of the §7.0 5-step pre-signing checklist
// (SPEC-COMPLIANCE-GUARD-M3 §15).

export const shredRegistryAbi = [
  {
    type: "function",
    name: "currentShredState",
    inputs: [{ name: "hCommit", type: "bytes32", internalType: "bytes32" }],
    outputs: [{ name: "", type: "uint8", internalType: "uint8" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "isShredded",
    inputs: [{ name: "hCommit", type: "bytes32", internalType: "bytes32" }],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "ShredStateChanged",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: true },
      { name: "hCommit", type: "bytes32", indexed: true },
      { name: "oldState", type: "uint8", indexed: false },
      { name: "newState", type: "uint8", indexed: false },
    ],
  },
] as const;
