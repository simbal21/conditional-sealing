// Trimmed ABI for `LitV3Assignment` — current-head + history reads
// + assignment events. Source: M2 ABI JSON.

export const litV3AssignmentAbi = [
  {
    type: "function",
    name: "getAssignment",
    inputs: [{ name: "authorizationId", type: "bytes32", internalType: "bytes32" }],
    outputs: [
      { name: "assignedTeeId", type: "bytes32", internalType: "bytes32" },
      { name: "assignmentBlock", type: "uint64", internalType: "uint64" },
      { name: "assignedTeePubkey", type: "bytes", internalType: "bytes" },
      { name: "sourceGovernanceDigest", type: "bytes32", internalType: "bytes32" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "assignmentHistoryLength",
    inputs: [{ name: "authorizationId", type: "bytes32", internalType: "bytes32" }],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "LitAssignmentRecorded",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: true },
      { name: "assignedTeeId", type: "bytes32", indexed: true },
      { name: "assignmentBlock", type: "uint64", indexed: false },
      { name: "sourceGovernanceDigest", type: "bytes32", indexed: false },
    ],
  },
  {
    type: "event",
    name: "LitAssignmentCorrectionRecorded",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: true },
      { name: "assignedTeeId", type: "bytes32", indexed: true },
      { name: "assignmentBlock", type: "uint64", indexed: false },
      { name: "sourceGovernanceDigest", type: "bytes32", indexed: false },
    ],
  },
] as const;
