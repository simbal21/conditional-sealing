> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Fresh adversarial audit — combiner / access-structure / g4-phase1 / ceremony
HEAD e87c108 · 2026-06-02 · read-only · Rule-45 verified against code

## Scope read
- pre-verify-pipeline.ts, profile-dispatch.ts, combine-and-decrypt.ts, sigma-orchestrator.ts,
  shamir-dispatch.ts, aead-decrypt.ts, gate-recipient-verifier.ts, snapshot-verifier.ts,
  plugin-integrity.ts (combiner)
- access-structure/policy-digest.ts
- g4-phase1/{adapter,mtls-https-transport,refusal-claim-verify,kem-binding-proof,sigma-verify}.ts,
  g4-shared/presign-checklist.ts
- v3-crypto/crypto/{aead,shamir}.ts, codecs/commit-aad.ts
- v3-api/{combiner-orchestrator/m3-bridge, reveal, vault/cealis-v3-vault}.ts
- v3-ops/ceremony/re-key-stanza-addition.ts

## FINDINGS

### F1 (MEDIUM, net-new) — G4 Phase 1 σ verified against caller-supplied authorityPubkey, never anchored to G4AuthorityRegistry
adapter.ts:90-106 `verifySigma` calls `verifyG4Phase1Sigma({... authorityPubkey: input.extras.authorityPubkey})`.
`input.extras.authorityPubkey` is caller-supplied (G4Phase1RequestExtras.authorityPubkey, adapter.ts:27).
The adapter fetches a registry entry (`fetchG4KemEntry` → getGateRecipientPubkeyAt) and passes it to
`verifyG4Phase1KemBindingProof`, but that proof binds only `entry.kemPubkey` (the KEM/encryption key) —
NOT the Ed25519 SIGNING key the σ verifies under. `GateRecipientPubkeyEntry` (types/gate-recipient.ts:91)
carries `kemPubkey` + `attestationRef` only; no signing pubkey. `getG4AuthorityAt` exists
(registry-reader.ts:251) but is never called in the σ-verify path, and `G4AuthorityEntry`
(types/registries.ts:28) carries `binaryHashOrMeasurement`, not a signing pubkey. presign-checklist.ts
never binds authorityPubkey/binaryHash to the registry's binaryHashOrMeasurement either.
=> A caller that supplies an attacker-chosen `authorityPubkey` makes verifySigma pass on an
attacker-forged σ. The σ-as-authorization gate verifies a signature against a key the caller picks.
Bounded by: (a) G4 Phase 1 is the pre-funding scaffold (Phase 2 TEE is the real non-custody claim);
(b) verifySigma's result is not yet wired into the shipping combine flow (see F4). Still: the gate is
not cryptographically anchored to chain. Fix: read the registered G4 authority signing pubkey at
authorizationBlock from G4AuthorityRegistry and verify σ against THAT, refusing any caller-supplied key.

### F2 (MEDIUM, net-new) — Combiner never re-binds on-wire commit_AAD bytes to the on-chain h_commit; commit_AAD round-trip is internal-consistency-only
pre-verify-pipeline.ts `verifyCommitAADRoundTrip` (253-321) proves only that
`encodeCommitAAD(decode(bytes)) == bytes` (skipping the version window). It NEVER compares `commitAADBytes`
against `commit_aad_digest` / the on-chain `h_commit`. The combiner takes `hCommit` as input
(combine-and-decrypt.ts) and threads it to gates + bundle, and sigma-orchestrator checks
`sigmas.hCommit === input.hCommit` (bundle self-consistency), but nothing binds the *commit_AAD bytes the
round-trip runs on* to h_commit. The vault is explicit it does NOT verify (cealis-v3-vault.ts:18-19,44):
it only guarantees bytes+digest travel together; `commit_aad_digest` is never consumed by the combiner.
`computeCommitContextDigest` is imported (m1-imports.ts:199) but never called in custody.
=> profile dispatch (FIXED_ONLY vs RECIPIENT_K_OF_N) is decided purely from attacker-suppliable
`commitAADBytes` not bound to chain. Concrete vector: take a real K_OF_N commit, flip the 2-byte
commit_version window 0x0302→0x0301. readCommitVersion returns 0x0301; decodeActiveCompatibleCommitAAD
patches it back to ACTIVE and decodes the real struct; commitVersion(0x0301) <= HISTORICAL_3GATE_MAX_VERSION
→ dispatched as `{kind:"FIXED_ONLY"}` (profile-dispatch.ts:66-72), dropping the conditional-recipient
gate requirement entirely. The round-trip PASSES because the version window is the one region it skips
(bytesEqualIgnoringVersionWindow, lines 333-341).
WHY IT IS NOT CRITICAL (verified): Shamir is 2-level (shamir.ts). K_OF_N seals the DEK as a 4-of-4
top-level combine {LIT,G3,G4,RECIPIENT_AGGREGATE} (degree-3 poly); FIXED_ONLY does a 3-of-3 combine
{LIT,G3,G4} (degree-2 poly). Interpolating 3 points of the degree-3 K_OF_N polynomial via combineFixedOnly
yields the WRONG constant term → wrong DEK → AEAD tag fail (aead.ts decryptPayload). The downgrade fails
closed on the implicit AEAD/Shamir barrier (acknowledged at profile-dispatch.ts:177-178 "implicit AEAD
defense only"). So this is a defense-in-depth gap, not a plaintext leak — but the system has ZERO
explicit barrier against commit_AAD substitution at the combiner; AEAD is the sole net. Fix: re-derive
h_commit from the on-wire commit_AAD bytes (computeCommitContextDigest already imported) and assert it
equals the on-chain-anchored hCommit before dispatch; gate the round-trip on commit_aad_digest too.

### F3 (LOW, net-new) — Historical 0x0301 decrypt path is structurally unreachable yet silently dispatched
profile-dispatch.ts decodeActiveCompatibleCommitAAD (222-228) PATCHES version→ACTIVE before decode, and
combine-and-decrypt passes the patched struct as the AEAD aad (decryptAeadPayload ← profileDispatch.commitAAD,
which encodeCommitAAD re-serializes with version=ACTIVE). A genuinely historical 0x0301 commit was sealed
with 0x0301 in its aad, so the patched-to-0x0302 aad will MISMATCH the seal-time aad → AEAD always fails for
real historical commits. The HISTORICAL_3GATE branch therefore cannot decrypt any genuine historical blob;
its only reachable effect is the F2 downgrade vector. Either the historical path is dead code that should be
removed/rejected outright, or it is missing the seal-time version in the aad (a real decrypt bug for any
0x0301 data). Fix: explicitly reject commitVersion < ACTIVE at the combiner (there is no live 0x0301 data —
ACTIVE was 0x0302 from first ship), which ALSO closes the F2 downgrade.

### F4 (INFO/HIGH-if-shipped, net-new) — σ-as-authorization gate trusts a metadata label; no production SigmaGatherer binds it to verifySigma
sigma-orchestrator.ts assertSigmaVerified (182-196) admits a σ iff `metadata.verified === "true"`. Nothing
in the shipping combiner-input assembly path SETS that flag from an actual verifySigma() call — the
SigmaGatherer (v3-api/combiner-orchestrator/sigma-gathering.ts:12) is an unimplemented interface with NO
concrete production implementation in the repo. So today the "primary gate-authorization check" (comment
line 187) is a label whose binding to real cryptographic σ verification does not yet exist in code. Fail-CLOSED
on missing flag is correct, but the flag→crypto binding is the load-bearing piece and it is absent. Flag now
(INFO at current build stage) so it is not forgotten when the gatherer ships — at that point this is the
single most security-critical seam in the combiner.

## Checked & CLEARED (fail-closed confirmed — NOT findings)
- readCommitContextDigest0 (aead-decrypt.ts:37) reads commit_context_digest_0 from attacker-influenceable
  σ-metadata, BUT it is the HKDF salt for the AEAD nonce (aead.ts:79-88); a wrong value → wrong nonce →
  AEAD fail. Fail-closed. Fallback is the authenticated endpoint_attestation_digest. Not exploitable.
- profile override (profile-dispatch.ts readProfileOverride 156-196): σ-metadata profileKind is fully
  label-only for ALL kinds (v0.3 closure); always returns {gateCount,historicalProfile} with no `profile`,
  so override?.profile at line 61 is always undefined → inferProfile is authoritative. Symmetric fix holds.
- k_conditional digest binding (policy-digest.ts + dispatchProfile + pre-verify re-assertion): correctly
  recomputes keccak256(jcs(policy)) and byte-compares to AAD-anchored digest, with n cross-check. Solid.
- mTLS transport (mtls-https-transport.ts): https.Agent with custom `ca` + default rejectUnauthorized=true
  (server cert IS validated against the private CA) + default checkServerIdentity (CN/SAN). Adequate for
  private-CA mTLS; no pinning beyond CA but that's acceptable. Minor robustness nit only: parseSignResponse
  casts `json.kemProof as G4Phase1KemDecapProof` unvalidated (line 222) — but it is re-verified downstream
  by verifyG4Phase1KemBindingProof, so a malformed proof fails closed there.
- refusal-claim-verify.ts: structural len/domain-tag/reason-range checks then Ed25519 verify over canonical
  bytes; try/catch around verify defaults sigOk=false. Fail-closed. (Authority pubkey is caller-supplied here
  too, but this is explicitly POST-HOC audit assurance, non-blocking per its own NON-GOALS — same key-anchoring
  concern as F1 applies if it is ever used as a gate.)
- re-key-stanza-addition.ts F-05 (h_commit_vN wrong preimage): KNOWN finding (TS-CRYPTO-F-05 marker), guarded
  by NODE_ENV=production tripwire that throws TRIPWIRE_BYPASS. Fails closed in prod. Not net-new.
- plugin-integrity.ts: binary-hash env overrides refused under NODE_ENV=production (F-07 closure). OK.
- canonical-address pin + chainId cross-substitution (pre-verify-pipeline.ts:107-114): mandatory, unconditional,
  fail-closed. OK.
