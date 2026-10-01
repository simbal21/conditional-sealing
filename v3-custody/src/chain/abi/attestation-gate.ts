// Trimmed ABI for `AttestationGate`. Source: M2 ABI JSON.
//
// NOTE: there is no on-chain `canGatesSign(authorizationId, blockNumber)`
// view. `canGatesSignAt` is a COMPOSITE SDK helper computed by the V3
// SDK from:
//   - `AttestationGate.authorizationBlock(authorizationId)` (pinned block)
//   - challenge state (read from `ChallengeRegistry`)
//   - shred state (read from `ShredRegistry`)
//   - refusal state (read from `G4RefusalRegistry`)
//   - finality depth (chain header)
//
// per the §7.0 5-step pre-signing checklist in
// SPEC-COMPLIANCE-GUARD-M3 §15.

export const attestationGateAbi = [
  {
    type: "function",
    name: "authorizationBlock",
    inputs: [{ name: "authorizationId", type: "bytes32", internalType: "bytes32" }],
    outputs: [{ name: "", type: "uint64", internalType: "uint64" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "AuthorizationBlockPinned",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: false },
      { name: "authorizationBlock", type: "uint64", indexed: false },
    ],
  },
] as const;
