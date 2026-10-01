> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Blast-Radius / Compartmentalization Matrix — Cealis V3

**Audit date:** 2026-05-14  
**Auditor:** Claude Code (read-only, code-verified)  
**Scope:** 4-gate AND-composition (G1 Chain + G2 Lit V3 + G3 dcipher/drand + G4 Cealis verify).  
**Evidence base:** V3 TypeScript (`v3-custody/`, `v3-crypto/`, `v3-api/`), Solidity contracts (`contracts/src/`), `SECURITY.md`, `contracts/DECENTRALIZATION-POSTURE.md`.  
**Key spec anchors:** S2-1 cryptography-spec, S2-2 smart-contracts-spec, S2-3 custody-integration-spec.

---

## Vector A — G4 Phase-1 Server Key Compromise

**Attack narrative.**  
An attacker obtains the Ed25519 signing key used by the Phase-1 G4 verification server. They can now produce arbitrary σ_G4 values. However, σ_G4 alone is one of three required Shamir shares (SHARE_ROLE_G4, logical index 2, x=3) that feed `combineDek`. The signing input for σ_G4 is bound per S2-1 §9 to the tuple `{binary_hash ‖ block_hash ‖ authorizationId ‖ h_commit ‖ timestamp}` — so the forged signature is scoped to a specific commit. The attacker still needs σ_Lit (x=1) and σ_G3 (x=2) to reconstruct the DEK; they cannot derive either.

**What is leaked.**  
Ability to forge σ_G4 for any authorizationId / h_commit pair (not replay — new signatures). No plaintext PII. No vault ciphertext. No σ_Lit or σ_G3.

**Additional compromise needed for PII.**  
G4 Phase-1 key + σ_Lit (from a compromised Lit TEE or operator) + σ_G3 (from dcipher/drand threshold). All three required. Any single missing gate → `reconstructFileKey` returns `ShamirCombineResult.ok = false` and throws `CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET` (`shamir-dispatch.ts:12`).

**Mitigations in code.**  
- Shamir enforce: `v3-custody/src/combiner/shamir-dispatch.ts:9` — `combineDek([...shares], profile)` is typed; wrong share count or wrong role returns `ok=false`.  
- Per-commit signing-input binding: `v3-crypto/src/signatures/sigma-g4.ts:107-118` — signing input = `binary_hash ‖ block_hash ‖ authorizationId ‖ h_commit ‖ timestamp`; reuse across commits is not possible without different per-commit inputs.  
- Chain-side G4 authority registry bounds who may sign: `contracts/src/registries/G4AuthorityRegistry.sol:80-93` — REGISTRY_ADMIN_ROLE (timelock-bound) required to add an authority entry; signature key must hash to `keccak256(TAG_G4_ATTESTATION_AUTHORITY_V3 ‖ authorityPubkey)` or `RegistryLookupKeyMismatch` reverts. Phase-1 servers carry `phase=1`; a Phase-1 server cannot impersonate a Phase-2 TEE.  
- G4 presign checklist: `v3-custody/src/g4-shared/presign-checklist.ts:55-60` — 5-step checklist requires chain-confirmed RevealAuthorized event (Step 1) before G4 will sign. Forged σ_G4 outside a valid RevealAuthorized window is useless because G1 hasn't fired.

**Residual risk.** **HIGH.** Phase-1 is operational-grade (sealed-code server), not cryptographic-non-custody. If the key leaks, the attacker has a permanently valid G4 signer for that key version. The mitigation is the AND-composition — they still need the other two gates. Rotation (new authority entry in G4AuthorityRegistry, 7-day timelock) is the incident-response path. Phase-2 HSM/TEE removes this risk entirely.

**Spec promise vs code reality.** PARTIALLY REALIZED. The AND-composition isolation is code-enforced (Shamir dispatch). The per-commit binding on the signing input limits forgery scope. However, Phase-1 is a server process with a software key, not a hardware-attested TEE — the key exists in memory and is extractable from a compromised host. Chain-side registry check bounds which keys are recognized as valid G4 authorities (provides revocation path), but does not prevent the attacker from signing during the window between compromise and revocation.

---

## Vector B — Combiner Host Compromise

**Attack narrative.**  
Root on the combiner process. The attacker observes the runtime: σ_Lit, σ_G3, σ_G4 arrive over the network during a reveal, along with the age envelope (ciphertext). They attempt to extract the DEK from memory during the combine step.

**What is leaked.**  
During an active reveal: all three gate σ values as they arrive (in-flight), the constructed Shamir share-records, and the reconstructed DEK (`result.dek: Uint8Array`) for the duration it lives in process memory before `zeroize`. The plaintext KYC payload is decrypted from the age envelope in the same process.

**For past commits (σ caching question).**  
There is no σ cache in the combiner for gate σ values. The code in `sigma-orchestrator.ts:70-71` explicitly calls `sigma.zeroize()` and `zeroize(evidence.sigmaBytes)` immediately after the share is recovered. Drand finality entries ARE cached (`v3-custody/src/g3-drand/finality.ts:20`), but these are threshold public outputs (chain hash + round + signature), not gate-signing secrets. No σ_Lit, σ_G3, or σ_G4 values are written to disk, DB, or logs by any V3 code path.

**Can attacker emit DEK bypassing FAIL-CLOSED.**  
The combiner is a network service that returns the decrypted plaintext to the caller. A root attacker can intercept the output. The runtime-hardening guards (`v3-custody/src/combiner/runtime-hardening.ts:31-39`) check for a `NETWORK_EGRESS_FLAG` but this is a Symbol-based flag checked via `globalThis`, not a kernel-level network restriction — root can bypass. Debug logging is also checked via env vars; root can set them.

**Additional compromise needed for PII of a PAST commit.**  
For past commits where no reveal is currently in progress, the attacker needs to forge all three gate σ values independently (no cached material). Past σ values are not stored. This is the AND-composition's durability guarantee.

**Mitigations in code.**  
- `sigma-orchestrator.ts:70-71` — zeroize on all σ bytes immediately after share recovery.  
- `runtime-hardening.ts:14-28` — `applyRuntimeHardening()` disables crash dumps (removes crash-dump PII path), suppresses SIGABRT/SIGQUIT (prevents coredump via signal), asserts debug logging disabled, checks network egress flag.  
- `combiner/pre-verify-pipeline.ts:72-74` — `assertShredStateSignable` and `rejectMode3` run before decryption; compromised combiner that skips these still cannot get gate σ values without upstream gate cooperation.  
- `combiner/cross-vendor-check.ts` — `assertCrossVendorTeeDisjoint` enforces vendor family separation for TEE-attested gates.

**Residual risk.** **HIGH** for in-flight reveals. Root on combiner = plaintext for that reveal's payload. **MEDIUM** for past commits (no stored σ material). The runtime-hardening mitigations are process-level not OS-level; root defeats them. This is an architectural limitation of combiner-hosted Shamir reconstruction — the DEK necessarily lives in combiner process memory during decryption.

**Spec promise vs code reality.** CONFIRMED COUPLING. Spec says "compromise of one component should not unlock plaintext." For a past/idle commit this holds. For an active in-flight reveal, combiner root = plaintext. This is not a code defect; it is the physical reality of a combiner-based decryption model. The isolation spec promise is CONDITIONAL on the commit not being in active reveal at time of compromise. Hardening paths exist but are process-level, not kernel or hardware.

---

## Vector C — V3 DB Compromise

**Attack narrative.**  
Attacker obtains a full PostgreSQL dump of `cealis_v3_dev` (or the Railway production equivalent).

**What is in the DB.**  
Per `v3-api/src/db/migrations/0001_ingestions.sql` and `v3-api/src/db/schema.ts`:

- `ingestions`: `h_commit` (commitment hash — public), `authorization_id`, `pda_id`, `partner_id`, `subject_commitment_v3` (per-partner derived hash — not plaintext identity), `vault_blob_ref` (reference to off-DB encrypted ciphertext, not the ciphertext itself), `schema_digest`, `commit_block`, `status`.
- `g4_attestation_cache`: `attestation_digest`, `commit_block`, `preflight_context_digest` — hash commitments, no key material.
- `reveals`: `bundle_digest`, `bundle_storage_ref` — post-reveal artifact digests and storage pointers.
- `partners`: `api_key_bcrypt` (bcrypt hash), `signing_secret_encrypted`, `webhook_secret_encrypted` — partner API secrets are stored encrypted/hashed, not in plaintext.
- `user_sessions`: SHA-256 hashed Bearer tokens (`schema.ts:137`).

**What is NOT in the DB.**  
- No vault ciphertext blobs (stored in a separate vault backend: S3/R2/IPFS per PDA, referenced by `vault_blob_ref`).
- No gate-recipient secret keys (ephemeral; never persisted).
- No σ values (not persisted per combiner zeroize discipline).
- No plaintext PII (mode_a ingestion sends plaintext to TEE boundary before DB write; plaintext destroyed after AEAD).
- No `subject_commitment_v3` raw identity material — the column holds `keccak256(TAG_SUBJECT_V3 ‖ personKey ‖ partnerNamespace ‖ registrationNonce)`, a keyed hash. `partnerNamespace` provides per-partner isolation per `CealisIdentifierHelpers.sol:22-37`.

**Additional compromise needed for PII.**  
DB dump + vault backend access (S3/R2) + all three gate σ values for each commit + combiner. The DB alone gives the attacker zero decryptable PII and zero key material.

**Mitigations in code.**  
- `subject_commitment_v3` privacy: `CealisIdentifierHelpers.sol:29-37` — per-partnerNamespace derivation; cross-partner correlation requires knowing both partnerNamespace and the personKey.  
- `vault_audit_log` append-only trigger (V1 carry pattern per `schema.ts:175`).  
- V3/V1 DB separation enforced by `SECURITY.md` (different databases, no shared schema).

**Residual risk.** **LOW** for PII exposure. **MEDIUM** for operational intelligence: the attacker learns which authorizations exist, which partners are active, vault blob storage locations (enabling targeted vault attacks), and (with `subject_commitment_v3`) can attempt to correlate subjects if they also compromised the partner's `partnerNamespace` secret. Session hijacking via hashed Bearer tokens requires preimage attack on SHA-256.

**Spec promise vs code reality.** REALIZED. DB holds no plaintext PII, no key material, no σ values. Vault references are pointers, not blobs. Subject identifiers are per-partner keyed hashes. Isolation is structurally enforced, not just policy.

---

## Vector D — Configurator Host Compromise

**Attack narrative.**  
Attacker gains control of the Cealis-internal PDA configurator and attempts to author a malicious PDA — e.g., one with `condition_module = AlwaysTrue` that immediately fires `RevealAuthorized`.

**Chain-side guardrail.**  
`ConditionEngine.sol:165` — `registerPDA` is gated to `ORCHESTRATOR_ROLE`. The condition modules are a fixed `address[9]` array set at `initialize()` time (`ConditionEngine.sol:76,114,145`). There is no `setConditionModule` function; the only upgrade path for modules is via UUPS upgrade through `MODULE_ADMIN_ROLE` which is held exclusively by the Timelock (7-day delay). An attacker with only configurator-host access cannot inject a custom module without also compromising the Timelock.

**Can they author a PDA with AlwaysTrue?**  
No, unless they also control the Timelock. The 9 module slots are fixed at deploy time. A malicious PDA must reference one of the 9 canonical `conditionModules[i]` addresses stored in the contract — it cannot reference an external `AlwaysTrue` contract because `registerPDA` calls into those fixed addresses via the `IConditionModule` interface.

**Can they fraudulently trigger a legitimate module (e.g., set PaymentObligation's payment flag)?**  
Depends on module. `OracleAttestationModule` requires a valid oracle signature (verified by `AttestationGate`). `TimeLockModule` requires `block.timestamp >= unlockTime`. `SubjectInitiatedModule` requires the subject's own σ_subject. Each module has its own authorization logic. Compromising the configurator alone does not provide module-fulfillment capability.

**Smallest PDA-induced damage.**  
A malicious PDA could be registered with a very short `timeCriticalPdaFlag` or `minimumShredLatency=0`, enabling rapid shred if the attacker also controls `shredAuthorityMode=Operator`. In `Operator` shred mode, Cealis can initiate shred unilaterally. If the configurator host is compromised alongside G4 ORCHESTRATOR_ROLE, an attacker could register a new PDA and shred it — destroying a subject's data without subject consent. This is DOS, not PII exfiltration.

**Mitigations in code.**  
- `ConditionEngine.sol:165` — `registerPDA` requires ORCHESTRATOR_ROLE.  
- `ConditionEngine.sol:145` — `_conditionModules` fixed at init; no post-init setter.  
- Timelock protects module upgrades: `MODULE_ADMIN_ROLE` is Timelock-only per `initialize` (line 127).  
- PDA `pda_root` hash must verify cryptographically: `ConditionEngine.sol:170-173` — `computedPdaRoot = _helpers.computePdaRoot(registration.pdaRootFields)` and mismatch reverts. Prevents post-registration PDA tampering.

**Residual risk.** **MEDIUM**. A configurator-host compromise alone cannot produce a PDA that bypasses module logic. It becomes HIGH if combined with ORCHESTRATOR_ROLE compromise (allows fraudulent registerPDA) or Timelock compromise (allows new modules). Shred-mode DOS is a real residual path if shredAuthorityMode is set to Operator in newly registered PDAs.

**Spec promise vs code reality.** LARGELY REALIZED. Module injection via PDA is blocked by the fixed module array. Fraudulent reveal requires both module condition satisfaction AND all gate σ values. Gap: no on-chain validation that a PDA's condition_module choice is sensible (e.g., a configurator could register a PDA with `minimumShredLatency=0` and `shredAuthorityMode=Operator` — valid per contract, undesirable operationally).

---

## Vector E — One Lit V3 TEE Operator Compromise

**Attack narrative.**  
DECENTRALIZATION-POSTURE.md states "~30 permissionless operators" for Lit V3. An attacker compromises one of these nodes and attempts to forge σ_Lit.

**Critical finding — Chipotle substrate pivot.**  
Internal research notes (2026-05-14) document that Lit Protocol V3 "Chipotle" has sunsetted the Datil multi-node threshold-signing model. Chipotle migrates G2 to a **single-TEE-enclave on Phala TDX + on-chain KMS** ("Proof of Cloud"). The 30-operator claim in DECENTRALIZATION-POSTURE.md describes the **old Datil model**, not the current Chipotle production state. The spec (S2-3 §G2) has not been backpropped to reflect this substrate change.

**If the old threshold model held:** Compromising one of N operators yields one partial Lit signature; threshold BLS prevents single-operator forgery. The threshold architecture would match the spec promise.

**Under Chipotle (current):** There is one TEE enclave per signing operation ("per-commit ephemeral"). If that single TEE is compromised during the window of a signing request, σ_Lit is forgeable for that commit. The attacker still needs σ_G3 and σ_G4 for PII — but the "30 compromise vectors" framing in the question is now inaccurate in the other direction: it is ONE Phala TDX enclave per-commit, not 30 independent nodes.

**What is leaked.**  
Under Chipotle single-TEE model: σ_Lit for the specific commit(s) processed in the compromised enclave during the attack window.

**Additional compromise needed for PII.**  
σ_Lit (from Chipotle TEE compromise) + σ_G3 (dcipher or drand threshold) + σ_G4 (G4 Phase-1 key) + combiner root.

**Mitigations in code.**  
- `cross-vendor-check.ts` — `assertCrossVendorTeeDisjoint` verifies G2 (Lit) and G4 (Phase-2 TEE) use different vendor families. This prevents G4 Phase-2 TEE compromise from simultaneously granting both σ_Lit and σ_G4.
- Per-commit ephemeral gate-recipient KEM keys: `v3-custody/src/combiner/gate-recipient-verifier.ts` — ephemeral keys mean a compromised enclave's key cannot be reused for other commits.
- S2-3 §G2 spec needs backprop to reflect Chipotle topology before partner deployment. **This substrate pivot was tracked as a pending internal issue.**

**Residual risk.** **HIGH** (spec/reality mismatch on threat model framing). Under Chipotle single-TEE, a single Phala TDX enclave compromise grants σ_Lit for in-flight commits. The AND-composition still requires G3 + G4, so PII is not exposed from G2 alone. But the decentralization claim ("30 permissionless operators") is stale, reducing G2's independent security contribution from a threshold network to a single attested enclave.

**Spec promise vs code reality.** UNVERIFIED at code layer — S2-3 §G2 was authored against the old Datil threshold model. The current Chipotle substrate is a single-TEE per signing operation. The isolation promise (TEE attestation bounds what code runs) survives this pivot; the decentralization claim does not.

---

## Vector F — One Oracle Key Compromise

**Attack narrative.**  
An oracle's secp256k1 signing key leaks. The attacker tries to submit fake attestations to unlock commits via `OracleAttestationModule`.

**What can the attacker do with a forged attestation?**  
`AttestationGate.sol:157-206` runs the full verification chain:
1. σ-shape guard: rejects 96-byte signatures (line 166).  
2. Oracle registry lookup at pinned `authorizationBlock` — oracle must be registered and non-deprecated.  
3. Schema validation.  
4. Freshness check: `_attestationObservedAt[digest] + maxAge < block.timestamp` reverts `AttestationStale` (line 193).  
5. Signature verification: ECDSA.recover against the oracle's registered pubkey (line 197-198).  
6. DSL claim evaluation: the claim predicate must evaluate to true (line 202).

**Is there single-use enforcement?**  
**FINDING:** The `AttestationGate` does NOT have a `_consumedAttestations` mapping. The audit prompt assumed this mitigation existed; code review of `AttestationGate.sol` confirms it does not. The contract instead uses a freshness window (`_maxAttestationAgeSeconds`, default 1 day) + lazy timestamp recording per digest (`_attestationObservedAt`). Replay is bounded only by the freshness window. An attacker with a valid oracle key can produce a fresh (distinct) attestation for each target `authorizationId` and is not blocked by any per-attestation consumption gate.

**Can the attacker submit a NEW attestation for a different authId?**  
Yes, if they have the oracle's key. They can produce a new `attestationDigest` covering a different `authorizationId` + claim, submit it via `OracleAttestationModule`. The oracle is registered in `OracleRegistry` — the key is valid until the oracle is deprecated (timelock-gated 24h expedited or 7-day normal path). The attacker can do this for any `authorizationId` whose PDA references that oracle.

**Additional compromise needed for PII.**  
Forged oracle attestation satisfies G1 (fires `RevealAuthorized`) — but the attacker still needs σ_Lit + σ_G3 + σ_G4 to reconstruct the DEK. `RevealAuthorized` alone does not release plaintext.

**Mitigations in code.**  
- `AttestationGate.sol:166` — 96-byte σ-shape guard blocks accidental gate-σ masquerade.  
- Oracle deprecation: `OracleRegistry` `deprecateEntry` (SECURITY_COUNCIL_ROLE or timelock) removes compromised oracle from valid set; `getOracleAt(id, pinnedBlock)` will then revert for new authorizations.  
- At-commit-block pinning: `AttestationGate.sol:111-116` — `setAuthorizationBlock` pins which block oracle lookup uses. This protects in-progress authorizations from retroactive oracle revocation, but also means revocation takes effect only for NEW authorizations (not existing ones using the old pinned block).

**Residual risk.** **MEDIUM**. Oracle key compromise can unlock G1 for any PDA referencing that oracle during the window before deprecation. PII requires also compromising G2+G3+G4. DOS path: attacker submits fraudulent PaymentObligation attestations to trigger spurious reveals or shreds, depending on PDA config. No cryptographic single-use enforcement per-attestation — only freshness window.

**Spec promise vs code reality.** PARTIAL COUPLING. Single-oracle key compromise enables unauthorized G1 firing for affected PDAs. The AND-composition prevents PII leakage. Absence of per-attestation single-use enforcement (the prompt expected a `_consumedAttestations` mapping) means a fresh forged attestation can be submitted for each target `authorizationId`. Deprecation path exists but requires 24h-7d window.

---

## Vector G — One TimelockController Proposer Compromise

**Attack narrative.**  
An attacker compromises an account holding the OZ `PROPOSER_ROLE` on `CealisTimelockController`. They queue a malicious operation — e.g., `grantRole(UPGRADER_ROLE, attacker)` — and wait for the 7-day delay to pass.

**Cancel path — does it exist and work?**  
The OZ `TimelockController` has a `cancel(bytes32 id)` function callable by `CANCELLER_ROLE` (`TimelockController.sol:27, 332`). In the OZ base constructor, `CANCELLER_ROLE` is granted to each account in the `proposers` array at deployment (`TimelockController.sol:127`). The `CealisTimelockController` extends this with expedited operations (24h, requires cosigner) but does not add a separate `CANCELLER_ROLE` assignment beyond what OZ provides. There is no explicit grant of `CANCELLER_ROLE` to a distinct security-council address visible in `PostDeploy.s.sol`.

**Consequence:** The cancel path exists via OZ base's `CANCELLER_ROLE`, but it is granted to proposers. If a proposer is compromised, they hold both PROPOSER_ROLE and CANCELLER_ROLE — they can queue AND cancel operations, giving them no countermanding capability from themselves. The `CealisSecurityMultisig` can queue expedited operations (it is granted `EXPEDITED_PROPOSER_ROLE` via `PostDeploy.s.sol:223`) but there is no evidence in `PostDeploy.s.sol` that `SecurityMultisig` is granted `CANCELLER_ROLE` on the base Timelock for normal-path operations.

**What can an attacker do in 7 days with a proposer key?**  
Queue any governance operation with a 7-day window (normal path). If SecurityMultisig lacks `CANCELLER_ROLE`, there is no on-chain cancel lever for the normal queue during that 7-day window.

**Additional compromise needed for real damage.**  
Post-7-day delay, execution requires `EXECUTOR_ROLE`. If that is also compromised, the attacker can execute. If `EXECUTOR_ROLE` is held by a separate party, the attacker queued the operation but cannot execute it alone.

**Mitigations in code.**  
- `CealisTimelockController.sol:51-62` — `NORMAL_GOVERNANCE_DELAY = 7 days` hard-coded; constructor reverts if supplied delay differs.  
- `PostDeploy.s.sol:223` — `SecurityMultisig` is an `EXPEDITED_PROPOSER_ROLE` holder, giving it the 24h expedited queue path.  
- `CealisSecurityMultisig.sol` — can trigger registry deprecations and expedited timelock operations but operates via its own surface, not the base timelock's `cancel()`.

**Residual risk.** **HIGH** if EXECUTOR_ROLE is co-held with PROPOSER_ROLE or if the attacker can wait 7 days. **MEDIUM** if EXECUTOR_ROLE is independently held and the 7-day window is monitored for malicious proposals. The absence of a confirmed SecurityMultisig → CANCELLER_ROLE grant for normal-path operations is a gap.

**Spec promise vs code reality.** CONFIRMED COUPLING. Grep across all non-library V3 Solidity (`grep -rn "CANCELLER_ROLE" contracts --include="*.sol" | grep -v lib/`) returned EMPTY. `PostDeploy.s.sol` grants `SecurityMultisig` only `EXPEDITED_PROPOSER_ROLE` (line 223) — no `CANCELLER_ROLE` grant exists anywhere in the codebase. The OZ base constructor grants `CANCELLER_ROLE` to each account in the initial `proposers` array, meaning proposers can cancel their own operations but there is no independent cancel authority held by `SecurityMultisig` for the normal 7-day queue. A compromised proposer can queue malicious operations that cannot be cancelled on-chain before execution — only monitored and socially escalated. This is a confirmed governance gap, not an unverified one.

**Action required (CONFIRMED GAP):** `PostDeploy.s.sol` does NOT grant `CANCELLER_ROLE` to `SecurityMultisig` — confirmed by code review. Must add `IAccessControl(addrs.timelock).grantRole(CANCELLER_ROLE, addrs.securityMultisig)` to `PostDeploy.s.sol` before mainnet deploy.

---

## Vector H — Old Vulnerable Plugin Still in PluginHashRegistry

**Attack narrative.**  
A security vulnerability is found in a previously registered plugin version. The old `canonicalBinaryHash` is still in `PluginHashRegistry`. Can a new commit use the old, vulnerable plugin version?

**How plugin version is bound.**  
A PDA commit includes a `pluginVersionDigest` in its `RegistryRefs` (`ConditionEngine.sol:85`). At `registerPDA` time, `_validateRegistration` calls `_touchRegistryRefs(registration.registryRefs)`, which calls `_registryReadAt(_pluginHashRegistry, refs.pluginVersionDigest, targetBlock)` (`ConditionEngine.sol:567-572`). This check uses `targetBlock = uint64(block.number)` — the current block, not a historical block.

**Can old plugin be used for new commits?**  
Yes, unless the old plugin entry is deprecated in `PluginHashRegistry`. `GovernedRegistry` (base of `PluginHashRegistry`) has a deprecation mechanism (`deprecateEntry`, `queueCanonicalDeprecation`) — once an entry is deprecated, `getEntryAt` reverts, causing `_touchRegistryRefs` to revert and blocking `registerPDA`. 

**For existing commits with old plugin version?**  
At `authorizeReveal` time (line 509), `_touchRegistryRefs(record.registryRefs)` is called again with `targetBlock = uint64(block.number)`. This means if the old plugin is deprecated AFTER a commit was registered, a subsequent `authorizeReveal` call for that commit WILL fail because the deprecated entry reverts at current block. The at-commit-block discipline for plugin verification is NOT applied at reveal time — it uses `block.number`, not the stored `commit_block`.

**Mitigations in code.**  
- `PluginHashRegistry` deprecation: canonical deprecations require 24h queue + Timelock; non-canonical deprecations can be done faster by SECURITY_COUNCIL_ROLE (`PluginHashRegistry.sol:113-115`).  
- Security Council can instantly deprecate a non-canonical plugin entry (`deprecateEntry` with `onlyRegistryRole(SECURITY_COUNCIL_ROLE)`).  
- The `_touchRegistryRefs` check at reveal-time (not just register-time) means deprecated plugins block reveals for pre-existing commits — protective against ongoing exploitation, but also means legitimate reveals on old-plugin commits break.

**Residual risk.** **MEDIUM**. An old plugin version can be used for NEW commits until deprecated. The deprecation mechanism provides incident response. However: (a) reveal-time check uses current block, not commit block — deprecated plugin also blocks reveals for legitimate pre-existing commits using that plugin, creating collateral damage during incident response. (b) The 24h/7d timelock on canonical deprecation creates a window where the vulnerability is known but the plugin remains valid for new commits.

**Spec promise vs code reality.** CONFIRMED COUPLING (intentional design choice with tradeoffs). The system does NOT bind commits to plugin versions at commit-block for reveal-time checks. Deprecated plugins block both new commits AND existing commits. This is protective against exploitation of existing commits but creates a conflict: reveals are blocked for legitimate users until a new commit is made with the upgraded plugin.

---

## Vector I — Vault Backend Compromise (S3 Bucket)

**Attack narrative.**  
Attacker gains read/write access to the S3/R2/IPFS bucket storing encrypted ciphertext blobs.

**Read access — can they decrypt blobs?**  
Each blob is AEAD-encrypted under the commit-specific DEK (ChaCha20-Poly1305 per S2-1 §8.3). The AEAD includes `commit_AAD` as associated data, bound to the specific `h_commit`, `pda_root`, `authorization_id`, and all gate identifiers. The DEK is derived from Shamir combination of gate signatures — inaccessible without all three gates. Ciphertext alone is computationally opaque.

**Write access — substitution attack.**  
If the attacker replaces a ciphertext blob with a different ciphertext, the AEAD decryption will fail at the combiner because `commit_AAD` will not match. The integrity of ciphertexts is protected by AEAD authentication: `v3-crypto/src/envelope/decode.ts:243-250` — `decryptPayload` returns a result with `ok: false` on any AEAD authentication failure. The combiner throws on `ok=false` results.

**DOS — blob deletion.**  
Yes. If the attacker deletes the blob from the vault backend, the reveal fails (ciphertext unavailable). This is a pure DOS with no PII leakage. Depending on vault backend choice (S3 versioning, IPFS immutability, Filecoin redundancy), recoverability varies.

**What is additionally needed for PII.**  
Blob (from vault) + DEK (requires all three gate σ values + combiner). Getting the blob does not help without DEK.

**Mitigations in code.**  
- AEAD AAD binding: `v3-crypto/src/codecs/commit-aad.ts:203` — `commit_AAD` encodes `h_commit`, `pda_root`, `authorization_id`, `subject_commitment_v3`, etc. Substitution of a different ciphertext breaks AEAD.  
- Stanza MACs: `v3-custody/src/combiner/pre-verify-pipeline.ts:100-107` — `verifyEnvelopeStanzaMacs` checked before payload decryption; MAC failure halts the entire reveal.  
- `vault_blob_ref` in DB is a reference, not the ciphertext itself; blob integrity is cryptographically verifiable via digest fields in `h_commit`.

**Residual risk.** **LOW** for PII exposure. **MEDIUM** for DOS availability (blob deletion with no redundancy). AEAD substitution attack is blocked by binding. Specific vault backend choice (versioning enabled on S3, IPFS immutability) determines DOS recoverability.

**Spec promise vs code reality.** REALIZED. AEAD binding prevents substitution. Deletion is a DOS path, not a confidentiality path. The spec's AAD-binding discipline is implemented correctly in v3-crypto AEAD primitives.

---

## Vector J — Subject Passkey Compromise

**Attack narrative.**  
The subject's passkey is compromised (credential extraction or cloning). The attacker can now authenticate as the subject and produce valid σ_subject.

**Cross-partner blast-radius.**  
V3 fixes V1 PRO-226. `CealisIdentifierHelpers.sol:29-37` — `subject_commitment_v3 = keccak256(TAG_SUBJECT_V3 ‖ personKey ‖ partnerNamespace ‖ registrationNonce)`. The `partnerNamespace` is a per-partner discriminator, and `registrationNonce` adds per-registration randomness. A passkey compromise on Partner A does NOT yield `subject_commitment_v3` for Partner B, because Partner B uses a different `partnerNamespace`. The attacker cannot link across partners from the passkey alone.

**Within-partner blast-radius.**  
σ_subject is required for `SubjectInitiatedModule` reveals and for certain challenge-resolution flows. A compromised passkey could allow the attacker to trigger a subject-initiated reveal (delivering the subject's own data to themselves or to whoever holds the gate recipient pubkeys). For other condition modules (PaymentObligation, TimeLock, etc.), σ_subject is not sufficient to trigger reveal — G1 chain condition must fire independently.

**Additional compromise needed for PII.**  
σ_subject alone does not produce PII. The attacker also needs σ_Lit + σ_G3 + σ_G4 + combiner access. Even for `SubjectInitiatedModule`, σ_subject satisfies G1 (fires `RevealAuthorized`) but all four gates must still sign before DEK is reconstructed.

**Mitigations in code.**  
- `CealisIdentifierHelpers.sol:29-37` — per-partner `partnerNamespace` prevents cross-partner linkability (addresses V1 PRO-226 explicitly per comment at line 23-27).  
- WebAuthn passkey is hardware-bound (phishing-resistant) per V3 design; cloning requires physical device compromise or backup extraction.  
- `PasskeyRotationLog.sol` — passkey rotation is on-chain logged, providing auditability.

**Residual risk.** **LOW** for cross-partner blast radius (fixed vs V1). **MEDIUM** for within-partner `SubjectInitiatedModule` reveals — passkey compromise enables the subject-initiated reveal flow without additional gates. For other modules, passkey alone does not fire G1.

**Spec promise vs code reality.** REALIZED for cross-partner isolation. V3 correctly implements per-partner derived subject commitments. Within-partner passkey risk is the expected design (subject agency) — not a spec violation.

---

## Summary

### Confirmed Isolation (Spec Promise REALIZED in Code)

| Vector | Isolation type | Evidence |
|--------|---------------|----------|
| **C (DB)** | No PII in DB; no key material | `0001_ingestions.sql` — no plaintext; `CealisIdentifierHelpers.sol:37` per-partner hash |
| **I (Vault)** | AEAD binding prevents substitution; blob alone is opaque | `v3-crypto/src/envelope/decode.ts:243-250`; `verifyEnvelopeStanzaMacs` |
| **J (Passkey)** | Cross-partner linkability fixed vs V1 PRO-226 | `CealisIdentifierHelpers.sol:29-37` — partnerNamespace isolation |
| **AND-composition** | Any single gate compromise insufficient for PII | `shamir-dispatch.ts:9` — `combineDek` requires all Shamir shares; error on `ok=false` |

### Unverified Isolation (Need Deeper Check)

| Vector | What needs verification | Why unverified |
|--------|------------------------|----------------|
| **E (Lit V3 operator)** | Whether S2-3 §G2 TEE model matches Chipotle single-TEE reality | Spec says 30-operator threshold; Chipotle (current) is single-TEE enclave on Phala TDX per internal research notes — requires S2-3 §G2 backprop; tracked as a pending internal issue |

### Confirmed Coupling (Where to Harden)

| Vector | Coupling type | Severity | Hardening path |
|--------|--------------|----------|----------------|
| **B (Combiner root)** | In-flight reveal: plaintext exists in combiner process memory during active decryption | HIGH | Process isolation (separate TEE for combiner), memory encryption; runtime-hardening is process-level not OS-level |
| **A (G4 Phase-1 key)** | Software key extractable from Phase-1 server process; key held in memory | HIGH | G4 Phase-2 HSM/TEE (removes software key); rotation path is 7-day timelock registry update |
| **G (Timelock proposer)** | `CANCELLER_ROLE` ABSENT from `PostDeploy.s.sol` for `SecurityMultisig`; confirmed by grep across all non-lib V3 Solidity (result: empty). No on-chain cancel lever for normal-path malicious proposals. | HIGH | Add `IAccessControl(addrs.timelock).grantRole(CANCELLER_ROLE, addrs.securityMultisig)` to `PostDeploy.s.sol` before mainnet |
| **F (Oracle key)** | No `_consumedAttestations` mapping in `AttestationGate.sol` (CONFIRMED ABSENT — code review, not an assumption). Fresh forged attestation valid for any PDA referencing that oracle until 24h-7d deprecation. | MEDIUM | Add per-authorizationId attestation consumption mapping in `AttestationGate`, or require attestation-to-authorizationId binding in oracle attestation digest |
| **H (Old plugin)** | reveal-time plugin check uses `block.number` not `commit_block`; deprecated plugin blocks legitimate reveals on pre-existing commits | MEDIUM | Distinguish plugin validation at register-time (current-block check appropriate) from reveal-time (commit-block check for existing commits); or implement separate grace-period for reveal of existing commits post-deprecation |
| **D (Configurator host)** | Shred-mode DOS possible if attacker has ORCHESTRATOR_ROLE and can register new PDAs with `shredAuthorityMode=Operator` + `minimumShredLatency=0` | MEDIUM (DOS) | Validate `minimumShredLatency` floor in `registerPDA`; require separate authority for Operator-mode shred registration |

### Critical Pre-Pilot Action Items

1. **CANCELLER_ROLE CONFIRMED ABSENT** — `PostDeploy.s.sol` does NOT grant `CANCELLER_ROLE` to `SecurityMultisig` for normal-path Timelock operations. Confirmed by code review (grep across all non-lib V3 Solidity returned empty). Add `IAccessControl(addrs.timelock).grantRole(CANCELLER_ROLE, addrs.securityMultisig)` to `PostDeploy.s.sol` before mainnet deploy.  
2. **S2-3 §G2 backprop** — update custody-integration-spec to reflect Chipotle single-TEE architecture; revise threat model for G2 from "30-operator threshold" to "single Phala TDX enclave per commit." Already tracked as a pending internal issue.  
3. **Oracle single-use** — `_consumedAttestations` mapping CONFIRMED ABSENT from `AttestationGate.sol`. Evaluate adding per-authorizationId attestation consumption enforcement; this closes the replay-via-fresh-forgery path.  
4. **G4 Phase-2 roadmap** — Phase-1 server key is the highest blast-radius single-key risk (HIGH). G4 Phase-2 (HSM/TEE) eliminates the software-key extraction path; maintain clear promotion schedule.
