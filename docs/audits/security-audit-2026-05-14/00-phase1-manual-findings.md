> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Phase 1 — Manual Security Audit Findings (2026-05-14)

**Auditor:** Claude Opus 4.7, manual grep-based + spec cross-reference scan
**Scope:** V3 contracts + V3 TS packages
**Method:** Targeted greps for known anti-patterns + spec cross-check on hot constructions
**Status:** Phase 1 only. Phase 2 (6 deep agents) hit Anthropic rate-limit and produced no output; will re-run with Sonnet workers after 5:50pm Berlin reset (now passed).

> **Deployment note:** any Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

---

## Baseline (NOT findings — confirmed clean)

| Check | Result | Evidence |
|---|---|---|
| Universal tripwire — only ConditionEngine emits `RevealAuthorized` | ✅ PASS | `engine/ConditionEngine.sol:213` is the only emit site; `IConditionEngine.sol:27` declares the event |
| Universal tripwire — only ConditionEngine emits `ShredAuthorized` | ✅ PASS | `engine/ConditionEngine.sol:245` only emit site; ShredRegistry has a `recordShredAuthorized` function (not event) for off-chain cascade |
| `tx.origin` usage | ✅ PASS | Zero occurrences across all `src/**/*.sol` |
| `delegatecall` usage | ✅ PASS | Zero occurrences across all `src/**/*.sol` |
| `selfdestruct` / `suicide` usage | ✅ PASS | Zero occurrences |
| UUPS `_authorizeUpgrade` role-gating | ✅ PASS | All 23 upgradeable contracts gate with `onlyRole(Roles.UPGRADER_ROLE)` |
| `initializer` modifier on every `initialize()` | ✅ PASS | All 30 `initialize()` functions use the `initializer` modifier |
| Proxy deploy pattern (atomic init) | ✅ PASS | `Deploy.s.sol:353` uses `new ERC1967Proxy(impl, initData)` with `abi.encodeCall(C.initialize, args)` — proxy initialization is atomic with deployment, no front-run window on the proxy itself |
| Postinstall scripts in V3 packages | ✅ PASS | Only `lib/openzeppelin-contracts/package.json` has `prepare`/husky (dev-only); zero postinstall in V3 application packages |
| Constant-time MAC comparison | ✅ PASS | `envelope/stanza-mac.ts:105`, `envelope/conditional-recipient-mac.ts:135`, `signatures/sigma-subject.ts:144`, `combiner/jcs-canonicalize.ts:58,69` — all use XOR-diff accumulator pattern (`return diff === 0`) which is constant-time |
| pnpm-lock.yaml present + committed | ✅ PASS | 260KB lockfile present at `pnpm-lock.yaml` |
| V1/V3 separation grep gate | ✅ PASS | All 4 forbidden patterns from SECURITY.md return zero matches: `@cealis/shared` imports, `../../packages/{V1}` reach-in, `GUARDIAN_*`/`ISSUER_SECRET_SALT`/`PK_COMMITTEE` env reads, V1 contract addresses |
| SD pipeline asymmetric isolation (SD-D9) | ✅ PASS | `v3-sd/src/boundary/boundary.ts:12-16` — if escrow fails, sd returns `"sd_skipped"`; SD errors return `SdFailure` rather than throwing, never propagating to escrow code |
| Hybrid PQ stanza wrap IKM byte ordering | ✅ PASS | Spec §6.2.3 line 1716 says `ikm = ss_x25519 ‖ ss_mlkem ‖ pk_eph_x25519 ‖ ct_mlkem`; code `v3-crypto/src/crypto/hybrid-wrap.ts:229` calls `concatBytes(input.ss_x25519, input.ss_mlkem, input.pk_eph_x25519, input.ct_mlkem)` — EXACT match. Confirms RFC 9180 HPKE pattern + ML-KEM-768 + X25519 hybrid wrap is byte-correct. |
| AEAD payload nonce HKDF | ✅ PASS | Spec §6.4.3 line 2081-2085 explicitly labels `ikm = DEK, salt = TAG_AEAD_V3 ‖ commit_context_digest_0, info = ""` to produce 12-byte nonce; code `v3-crypto/src/crypto/aead.ts:79-89` matches exactly (DEK is 2nd `hkdf` arg = ikm, TAG‖digest is 3rd arg = salt). |
| SD salt derivation domain separation | ✅ PASS | Per `v3-sd/src/m1-imports.ts:56-59`, `sd_master_salt = HKDF-SHA256(salt=TAG_SD_SALT_V3 ‖ sd_salt_context_digest, ikm=DEK, info="cealis-sd-master-salt-v3", L=32)` — TAG-prefix + DEK-as-IKM ensures cross-context isolation from AEAD nonce derivation. |

---

## Findings

### F-01 [MEDIUM] Implementation contracts not locked via `_disableInitializers()`

**Files:** 30 upgradeable contracts across `contracts/src/**/*.sol` — none has a constructor calling `_disableInitializers()`.

**Concrete list (every UUPS contract):**
DisclosureRegistry, DisclosureRevocationRegistry, G4AuthorityRegistry, OracleSchemaRegistry, LitV3Assignment, OracleRegistry, PluginHashRegistry, DSLVersionRegistry, PasskeyRotationLog, SupersededCommitRegistry, QTSPRegistry, GateRecipientPubkeyRegistry, G4RefusalRegistry, AttestationGate, EmergencyGovernance, FSMInterpreter, CealisSecurityMultisig, ShredRegistry, ChallengeRegistry, HeartbeatMissedModule, DeadManSwitchModule, PaymentObligationModule, OracleAttestationModule, ConsentGateModule, MultiPartySignalModule, TimeLockModule, SubjectInitiatedModule, ConditionEngine, ComposedModule, ClaimDSL.

**What's wrong:** The proxy is initialized atomically at deployment (good), but the IMPLEMENTATION contract itself is left in an un-initialized state. Per OpenZeppelin's standard pattern for upgradeable contracts:
```solidity
constructor() {
    _disableInitializers();
}
```
This locks the implementation so `initialize()` cannot be called directly on it post-deployment.

**Why it matters:** Without `_disableInitializers()`, an attacker can call `initialize(...)` directly on the implementation contract's address (not the proxy) and seize impl-side roles (DEFAULT_ADMIN_ROLE, UPGRADER_ROLE). With OZ UUPSUpgradeable v5.x's `onlyProxy` modifier on `upgradeToAndCall`, the attacker CANNOT trigger an upgrade on the proxy from the impl-side admin role — so the proxy state is safe.

**Real risk surface:**
1. **Auditor signal:** ToB, Consensys Diligence, Spearbit will ALL flag this as a finding. It's a defense-in-depth gap and a standard pattern violation.
2. **Defense-in-depth:** If any future OZ change introduces a new function where impl-side roles matter, exposure opens silently. Hardening now is cheap.
3. **Indirect attacks:** An impl with admin role could be used as a "trustworthy-looking" contract in a social-engineering scenario (the impl address is visible on-chain and looks legitimate).

**Fix:** Add to each contract's constructor:
```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```
The OZ NatSpec directive suppresses the upgrades-plugin warning about constructors in upgradeable contracts.

**Effort:** ~30 minutes, 30 small edits, no logic change. Re-run forge tests to confirm no regressions.

**Confidence:** HIGH that this is a real best-practice gap. MEDIUM that it's exploitable today; HIGH that an auditor will flag it.

---

### F-02 [MEDIUM] Oracle attestation digests not bound to `chainid`

**Files:**
- `attestation/AttestationGate.sol:254` — `ECDSA.recover(attestationDigest, oracleSignature)` verifies the oracle's signature on `attestationDigest`
- Spec `docs/specs/cryptography-spec.md §2.3.4` defines `TAG_G4_ATTESTATION_V3 = "CEALIS_V3_G4_ATTESTATION_V3"` — protocol-level domain separator, NOT chain-level

**What's wrong:** The TAG_*_V3 domain separators prevent cross-PROTOCOL replay (signature for Cealis can't be used as a signature for X). But `block.chainid` is NOT included in the digest preimage. The only on-chain use of `block.chainid` is in `CealisSecurityMultisig.sol:169` for the multisig's own EIP-712 domain.

**Why it matters:** An oracle signature produced for `OracleRegistry@Base-Sepolia` (chainId 84532) is byte-identical to one produced for `OracleRegistry@Base-Mainnet` (chainId 8453) IF the oracle's pubkey, schema, and attestation payload are the same. The mitigations that exist:
1. `_consumedAttestations` mapping is single-use per chain (prevents re-replay on same chain)
2. Each chain has independent OracleRegistry deployments → the oracle would have to be registered on both chains for the digest to verify
3. Attackers must control oracle off-chain process to weaponize

**Residual risk:** "Cross-environment replay" — e.g., an oracle attests on Base Sepolia for testing; attacker captures the digest+signature; if the SAME oracle is later registered on Base Mainnet under the same key and the SAME attestationDigest construction (which uses authorization-specific inputs not seen as testnet vs mainnet), the signature is valid on mainnet. The oracle's off-chain discipline (different keys per environment) is the only line of defense.

**Fix:** Two options:
1. **Include `block.chainid` in the on-chain reconstruction of the attestation digest preimage** — i.e., the chain re-derives the expected digest from oracle-supplied inputs + chainid, and verifies the oracle signed that derivation. Forces oracle to commit to chainid.
2. **Operational mitigation:** Document that oracles MUST use per-chain signing keys + per-chain attestation pipelines. (Lower assurance than crypto-enforced.)

Recommendation: Option 1, on next deploy cycle. Spec amendment to TAG_G4_ATTESTATION_V3 preimage form.

**Effort:** ~2-4 hours including spec patch + contract change + oracle SDK update.

**Confidence:** MEDIUM that this is exploitable in the wild today (oracle-side discipline matters). HIGH that this is a defense-in-depth gap.

---

### F-03 [LOW] Caret semver on critical crypto deps in `v3-crypto`

**File:** `v3-crypto/package.json`

Pinned with `^` (allows minor/patch upgrades silently):
```
"@noble/hashes": "^1.7.0",
"@noble/curves": "^1.6.0",
"@noble/ciphers": "^1.2.0",
"@noble/post-quantum": "^0.5.0",
"@scure/base": "^1.2.0",
"@simplewebauthn/server": "^13.3.0"
```

All other V3 packages (`v3-custody`, `v3-api`, `v3-configurator`, `v3-ops`, `v3-sd`, `verify-sdk`, `v3-demo`) use exact pins (`"@noble/hashes": "1.8.0"`).

**Why it matters:** Caret semver permits silent minor-version upgrades on `pnpm install` (without `--frozen-lockfile`). The currently-locked versions (`@noble/post-quantum@0.5.4`) are consistent with the exact-pinned packages, so CURRENTLY there's no inconsistency. But:
1. Anyone running `pnpm update` will silently bump v3-crypto's deps to new minor versions while leaving other packages on the exact pin → introduces version skew silently
2. Supply-chain attacks land via minor-version "looks-fine" updates
3. Inconsistent pinning discipline across the monorepo is a yellow flag in audits

**Fix:** Tighten v3-crypto to exact pins matching the rest of the monorepo. ~5 minute edit.

**Confidence:** HIGH that this is a discipline gap. LOW that it's exploited today (lockfile is committed).

---

### F-04 [LOW] Dual `@noble/curves` versions in dep tree (defense-in-depth)

**Evidence:**
- All V3 packages directly depend on `@noble/curves@1.9.7`
- `@noble/post-quantum@0.5.4` brings in `@noble/curves@2.0.1` as transitive

```
'@noble/post-quantum@0.5.4':
  dependencies:
    '@noble/curves': 2.0.1
```

**Why it matters:** pnpm isolates dep versions per package, so this works at runtime. But:
1. **Audit surface increase:** Two versions of a security-critical lib in one tree = double the code to vet
2. **Future-drift:** If you ever switch to npm hoisting or flat deps, you'd hit a conflict
3. **Inconsistency principle:** "Why are TWO versions of a single crypto lib in the tree" is a question auditors will ask

**Why @noble/post-quantum is 0.x and uses curves 2.0.1:** ML-KEM is a newer primitive; the package is pre-1.0 and tracks a different release cadence. Acceptable but worth tracking.

**Fix options:**
1. Wait — when @noble/post-quantum hits 1.0 and depends on curves 1.x, this collapses
2. Upgrade all direct curves usage to 2.x (requires API audit of @noble/curves 1.x → 2.x changes)
3. Pin `@noble/post-quantum` to a version that uses curves 1.x (if any) — likely doesn't exist
4. Document this as accepted risk

**Recommended:** Accept now (defense-in-depth gap), revisit when @noble/post-quantum reaches 1.0.

**Confidence:** HIGH that the dep tree is split. LOW severity.

---

### F-05 [COSMETIC] Hand-rolled constant-time MAC comparison

**Files:**
- `v3-crypto/src/envelope/stanza-mac.ts:105`
- `v3-crypto/src/envelope/conditional-recipient-mac.ts:135`
- `v3-crypto/src/signatures/sigma-subject.ts:144`
- `v3-custody/src/combiner/jcs-canonicalize.ts:58, 69`

**Pattern:** Manual XOR-diff accumulator → `return diff === 0`

**Why it matters:** Mathematically constant-time, but auditors prefer the Node-native `crypto.timingSafeEqual()` which is documented constant-time and harder to accidentally break in a refactor.

**Fix:** Replace with `crypto.timingSafeEqual(a, b)`. ~10 minutes.

**Severity:** COSMETIC. Already secure; this is clarity-of-intent.

---

## What Phase 1 didn't cover (deferred to Phase 2 with Sonnet workers)

| Lens | Why Phase 2 needed |
|---|---|
| Cross-contract reentrancy via call graphs | Requires reading + walking ConditionEngine ↔ FSMInterpreter ↔ ClaimDSL ↔ modules — needs sustained context |
| AAD canonicalization byte-by-byte | Needs reading commit-aad.ts + pda-root.ts in full alongside spec §3.4 / §17.2 |
| Hybrid KEM IKM ordering (S2-1 §6.2.3) | Needs reading hybrid-wrap.ts + spec §6.2.3 in full |
| Shamir parameter correctness (threshold 3+k of 3+n) | Needs reading shamir.ts in full alongside spec §8.3 |
| σ-as-AUTHORIZATION vs legacy σ-as-IKM | Needs verifying May 5 doctrine flip is fully realized |
| PDA validation 5-stage layered gate (S2-4 §5) | Needs reading v3-configurator validation pipeline |
| Combiner FAIL-CLOSED 4-check (S2-3 §5) | Needs reading combiner/sigma-orchestrator.ts |
| Cross-vendor TEE disjoint mandate | Needs reading attestation verifier + vendor-family normalization |
| Blast-radius matrix (12 compromise vectors A-L) | Needs deep cross-component reasoning |
| Supply chain transitive audit | Mechanical but tedious — Sonnet ideal |
| Replay protection on attestation digests across (chain, authId, nonce) | Needs reading every signature-verifying contract |
| Role escalation paths through grant chains | Needs walking AccessControl grants |

---

## Re-spawn plan (Phase 2)

Re-spawn 6 Sonnet-based agents (cheaper, equally capable for mechanical lens scans):
1. solidity-auditor lens 1+3+4+5+10 (cross-contract reentrancy, role separation, sig replay, snapshot-vs-recheck, tripwire)
2. typescript-architect on v3-crypto + v3-custody (AEAD, AAD, Shamir, hybrid PQ)
3. typescript-architect on v3-api + v3-configurator + v3-sd + verify-sdk (boundaries, PDA validation, SD isolation)
4. general-purpose Sonnet on blast-radius (vectors A-L)
5. general-purpose Sonnet on cross-stack + supply chain detail
6. spec-to-code-compliance on byte-exact crypto constructions

Then consolidate + propose remediation PR.
