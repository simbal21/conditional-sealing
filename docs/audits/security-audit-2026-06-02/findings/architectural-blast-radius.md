> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Architectural Blast-Radius Audit — HEAD e87c108 (2026-06-02)

Read-only fresh-lens audit. Verdict basis = actual code at HEAD via grep/read (Rule 45).

## Trust-boundary blast-radius matrix

| Boundary | Single-compromise yield | PII plaintext? | Forge RevealAuthorized? | Bypass shred guardrail? | DOS? |
|---|---|---|---|---|---|
| **G4 Phase-1 host (daemon)** | Signs σ over caller-supplied presign booleans; never reads chain itself | No (only 1 of 3+ shares; needs Lit+G3 too) | No (cannot emit on-chain event) | No alone (combiner re-reads shred live) — but daemon trusts caller presign incl. `shredStateSignable`, so it will sign even when shredded; blast contained by combiner-side live read | Yes (refuse to sign halts reveal — by design) |
| **Combiner host** | Supplies registry snapshots + deployment manifest (non-ConditionEngine addresses); runs all live chain reads; runs the σ→share→DEK reconstruction | YES if it also obtains the 3 gate shares (it is the assembly point) | No (event is on-chain) | YES — supplies AuthorizationRegistrySnapshot incl. currentShredState; only ConditionEngine address is compile-pinned, shredRegistry address is manifest-injectable | Yes |
| **Oracle key / configurator** | Configurator chain-emit is `mockRegisterPDA` (chainId 31337), signature is a keccak hash not a real sig — STUBBED, no live authority | No | No | No | n/a (not live) |
| **ORCHESTRATOR_ROLE / API host** | Production reveal path `wireProductionDeps()` throws NOT-YET-WIRED; `processRevealAuthorizedEvent` takes `full_plaintext` + precondition booleans directly | (future) — see F-API-1 | No | (future) | Yes |
| **Vault backend** | Opaque ciphertext + commit binding only; never sees DEK/plaintext | No | No | No | Yes (withhold ciphertext) |
| **DB** | Status/manifest/bundle records | No (no key material) | No | No | Yes |
| **Each single gate operator (Lit / G3 / G4)** | One Shamir share role | No — `combineDek` requires Lit+G3+G4 roles, threshold 3 (FIXED_ONLY) / 4 | No | No | Yes (withhold → threshold not met) |

## Confirmation: 4-gate AND compartmentalization HOLDS in reconstruction logic

`v3-crypto/src/crypto/shamir.ts` `combine()` → `combineFixedOnly` requires SHARE_ROLE_LIT + SHARE_ROLE_G3 + SHARE_ROLE_G4 (threshold 3); `combineRecipient1Of1`/`combineRecipientKOfN` require those 3 PLUS recipient aggregate (threshold 4). `missingMandatoryTopRoles` + `isSubstitutionAttempt` (l.255-273) defeat the "drop a mandatory top-level branch and substitute recipients" attack. No single gate share reconstructs the DEK. The AEAD payload (`aead-decrypt.ts` → `decryptPayload`) is authenticated under commit_AAD so a wrong DEK fails closed. **This is sound by inspection.**

BUT: this is the CONSUMER side only. See F-CRYPTO-2 — no producer (commit-time DEK-dealing) exists and the only "integration" test sets every gate share = the full DEK (`combiner-testkit.ts:232 shareHex: bytesToHex(DEK)`), which is NOT a real Shamir split, so the AND is not validated against a real split end-to-end.

---

## NET-NEW FINDINGS

### F-CRYPTO-1 (HIGH) — Combiner binary self-attestation is a production no-op (tautological compare)
`v3-custody/src/combiner/plugin-integrity.ts:42-49`
`verifyPluginIntegrity` claims to self-attest the running combiner binary against the on-chain `PluginHashRegistry` entry (TS-CRYPTO-F-07 was supposed to close this). In production (no `CEALIS_COMBINER_BINARY_HASH`/`_SEED` env), `computeCanonicalBinaryHash(entry.binaryHashOrMeasurement)` returns `hexToBytes(fallbackExpected)` = `hexToBytes(entry.binaryHashOrMeasurement)`, then compares it via `bytesEqual` against `hexToBytes(entry.binaryHashOrMeasurement)` — i.e. the registry value compared to itself. There is NO measurement of the actually-running code (no `process.execPath`, no `readFileSync` of own bundle, no TEE quote — confirmed by grep, zero hits in combiner/). A combiner host running tampered code (e.g. one that exfiltrates the reconstructed DEK/plaintext) passes this check unchanged. The on-chain plugin-hash binding constrains nothing at runtime.
Compounding: `assertNoBinaryHashOverridesInProduction` is never called at any bootstrap (grep: zero callers outside its own file/tests), so even the env-override guard is dangling.

### F-CRYPTO-2 (MEDIUM) — No commit-time DEK-dealing producer; AND tested only with degenerate shares
`v3-custody/tests/integration/combiner-testkit.ts:232`; `v3-demo/src/rounds/round1.ts:216`
There is no commit-time Shamir-dealing / DEK-split producer anywhere in v3-crypto (grep for splitDek/shamirSplit/dealShares = 0). `combineDek` (consumer) is complete, but the only test exercising the combiner sets every gate's `shareHex = bytesToHex(DEK)` (all shares carry the full DEK, so Lagrange of the constant polynomial trivially returns DEK), and the demo only does `void combineAndDecrypt` as an importability anchor — it never runs a real reveal. Consequence: the AND-compartmentalization is asserted by reconstruction-code inspection but never validated against a genuine n-of-n split where shares are distinct and individually useless. A producer/consumer wire-format mismatch (share x-coordinate, role tagging, byte-lane order) would not be caught until first pilot.

### F-COMBINER-1 (HIGH) — Only ConditionEngine address is compile-pinned; shred/refusal/pubkey registry addresses remain manifest-injectable
`v3-custody/src/chain/canonical-addresses.ts:33-41`; `v3-custody/src/chain/registry-reader.ts:148-155, 189, 422, 458`
The TS-CRYPTO-F-08 fix pins ONLY `conditionEngine` per chainId. Every other registry the combiner reads — `shredRegistry`, `g4RefusalRegistry`, `gateRecipientPubkeyRegistry`, `attestationGate`, `pluginHashRegistry` — is sourced from `config.addresses` (the user-injectable deployment manifest). The shred guardrail reads `this.addresses.shredRegistry` (registry-reader.ts:458 `getCurrentShredState`) and refusal reads `this.addresses.g4RefusalRegistry` (l.422). A poisoned manifest can point `shredRegistry`/`g4RefusalRegistry` at an attacker contract that always returns `None`/`not-refused`, defeating the shred-mid-reveal guardrail and G4 legal-compel refusal — while the ConditionEngine pin still passes, so the combiner believes it is on the canonical deployment. This is exactly the manifest-injection attack class F-08 was raised to close, left open for the non-ConditionEngine registries.

### F-COMBINER-2 (MEDIUM) — Combiner runtime-hardening egress/IPC blocks are cosmetic in production
`v3-custody/src/combiner/runtime-hardening.ts:31-43, 68-75`
`applyRuntimeHardening()` returns `networkEgressBlocked: true` / `ipcExportBlocked: true` but enforces nothing real: `assertNoNetworkEgress` only checks a `globalThis` symbol that is set EXCLUSIVELY by `setNetworkEgressForTest` (grep confirms no production setter), and the IPC check only fires on a self-set `CEALIS_COMBINER_IPC_ACTIVE` env flag. No actual socket/syscall interception exists. The combiner's stated defense — "σ values and the reconstructed DEK/plaintext cannot be exfiltrated off the σ path" — is not implemented; a tampered or malicious-dependency combiner can open a socket and ship the DEK with these asserts still passing. (Pairs with F-CRYPTO-1: together they mean the combiner host is an unconstrained single point for PII once the 3 shares are present, with no runtime defense and no binary attestation.)

### F-G4-1 (LOW / phase-honest) — G4 Phase-1 daemon trusts caller-supplied chain-state booleans (`body.presign`)
`v3-custody/g4-phase1/server/presign-checklist.ts:9-15`; `server/main.ts:83`
The daemon `/sign` route runs `assertServerPresignChecklist(body.presign)` over five caller-supplied booleans (`finalized`, `challengeWindowClosed`, `canGatesSign`, `shredStateSignable`, `blockingRefusalActive`) and signs if they pass — it performs NO independent chain read. Whoever calls the daemon (the combiner/orchestrator host) decides whether the daemon signs. This is the documented Phase-1 limitation (Phase-2 TEE is the cryptographic-refusal answer), and the combiner-side `runG4PresignChecklist` does read chain for steps 3-5, so the net new risk is bounded to: a compromised combiner host can extract a valid G4 σ at will (the G4 "independent refusal" property does not exist in Phase 1). Flag as LOW because it is phase-honest and disclosed, but it means the pilot's G4 gate adds no independent-verification value beyond the combiner host's own honesty.

### F-API-1 (MEDIUM, forward-wiring risk) — Cryptographic combiner is decoupled from the live reveal/clearance path
`v3-api/src/combiner-orchestrator/m3-bridge.ts:100` (only definition, zero production callers); `v3-api/src/combiner-orchestrator/index.ts:61,168` (`full_plaintext` is a direct input); `v3-api/src/reveal/reveal-coordinator-impl.ts:322` (`buildCombinerInput` is an injected closure)
`runM3CombinerBridge` (the function that actually calls `combineAndDecrypt`) has no caller anywhere in production code (grep: only m3-bridge.ts itself). The live reveal path (`/internal/reveal/initiate` → `persistAndDeliver` → `processRevealAuthorizedEvent`) obtains `full_plaintext` from an injected `buildCombinerInput` closure and asserts only caller-supplied precondition booleans (`assertRevealPreconditions`, index.ts:256). The elaborate C3a type-level "forced fresh GateClearance" discipline gates DELIVERY but is structurally independent of whether the plaintext was produced by the cryptographic 4-gate combiner. Production wiring is currently `wireProductionDeps()`-throws (bin.ts:58), so this is not live today — but nothing in the type system forces the eventual worker-2/4 wiring to route `buildCombinerInput` through `combineAndDecrypt`. Net-new SPOF latent in the seam: the API can be wired to deliver PII assembled from `full_plaintext` without ever invoking the gate-AND. Recommend a type-level or test-level invariant binding `full_plaintext` provenance to a `combineAndDecrypt` result before pilot.

### F-COMBINER-3 (LOW) — Cross-vendor TEE-disjoint mandate disabled for the pilot phase + sourced from σ-metadata
`v3-custody/src/combiner/cross-vendor-check.ts:13-18`
`assertCrossVendorTeeDisjoint` returns early when `commitAAD.phase === 1` (the pilot phase), so Lit/G4 vendor-family disjointness is not enforced at pilot. In Phase 2 it reads `litVendorFamily`/`g4VendorFamily` from σ-metadata (`findMetadata` over evidence) — attacker-influenceable bag — rather than from an AAD-anchored field. Effect: the "a single TEE-vendor compromise cannot control both Lit and G4" compartmentalization is (a) off in Phase 1 and (b) in Phase 2 trusts metadata that isn't digest-bound to the on-chain commit (contrast the k_conditional fix in profile-dispatch which WAS moved to an AAD-digest-bound field). LOW because Phase-1 G4 is a server not a TEE anyway, but the Phase-2 σ-metadata trust is the same trust-by-default class that R2b-3 closed for the threshold.

## Recommended fixes (summary)
- F-CRYPTO-1: implement a real running-code measurement (read own bundle / TEE quote) OR drop the false "self-attestation" claim from WP/docs; wire `assertNoBinaryHashOverridesInProduction` at bootstrap.
- F-COMBINER-1: compile-pin ALL combiner-consumed registry addresses per chainId (extend CANONICAL_ADDRESSES), or derive them from the pinned ConditionEngine via on-chain registry-of-registries; assert manifest addresses == pinned.
- F-CRYPTO-2: build the commit-time DEK-dealing producer and add an end-to-end test with distinct, individually-useless shares; remove the DEK-as-share testkit shortcut for the AND assertion.
- F-COMBINER-2: implement real egress/IPC interception in the combiner sandbox (or run in a network-namespace-isolated container) and have the asserts read true state; otherwise remove the misleading hardening claims.
- F-API-1: bind `full_plaintext` provenance to `combineAndDecrypt` at the type or test level before production wiring.
- F-COMBINER-3 / F-G4-1: track as phase-honest; move Phase-2 vendor-family to an AAD-digest-bound field; document Phase-1 G4 as non-independent.
