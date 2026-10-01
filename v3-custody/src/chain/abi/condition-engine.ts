// Trimmed ABI for `ConditionEngine` — only the `RevealAuthorized` event
// (and `RevealCompleted` for completeness). Source: M2 ABI JSON.
//
// Per S2-2 §0.7 + §12.1 (universal tripwire): only `ConditionEngine`
// emits `RevealAuthorized`. The V3 SDK subscribes to this event for
// reveal triggers — see `subscribeRevealAuthorized` in registry-reader.ts.

export const conditionEngineAbi = [
  {
    type: "event",
    name: "RevealAuthorized",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: true },
      { name: "hCommit", type: "bytes32", indexed: true },
      { name: "pdaRoot", type: "bytes32", indexed: true },
      { name: "authorizationBlock", type: "uint64", indexed: false },
      { name: "authorizationTimestamp", type: "uint64", indexed: false },
      { name: "challengeWindow", type: "uint32", indexed: false },
      { name: "conditionRef", type: "bytes32", indexed: false },
    ],
  },
  {
    type: "event",
    name: "RevealCompleted",
    inputs: [
      { name: "authorizationId", type: "bytes32", indexed: true },
      { name: "deliveryDigest", type: "bytes32", indexed: false },
    ],
  },
] as const;
