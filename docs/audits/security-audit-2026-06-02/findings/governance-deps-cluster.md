> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Governance + Deps Cluster — Reconciliation vs HEAD e87c108 (2026-06-02)

Read-only audit. Verdicts are grep/read against HEAD, not old finding text (Rule 45).

## BR-G (HIGH) — CANCELLER_ROLE to SecurityMultisig — FIXED
`script/PostDeploy.s.sol:234-237` grants `TimelockController.CANCELLER_ROLE()` to
`addrs.securityMultisig` in `_configureGovernance`. Comment block 228-233 cites the
exact BR-G rationale (OZ grants CANCELLER to every proposer at construction → compromised
proposer can queue+cancel; independent canceller closes single-actor capture). Patched, confirmed.

## G4RefusalRegistry OPERATOR_ROLE — FIXED
`script/PostDeploy.s.sol:252` — `_grant(addrs.g4RefusalRegistry, Roles.OPERATOR_ROLE, operator)`
inside `_grantOperationalRoles`. Matches the Rule-documented PostDeploy:252 claim. The
`initialize` only grants admin/upgrader (correct scoping per the rules/solidity.md
"Audit Finding Cross-Check Discipline" note). NOT-APPLICABLE as an open finding.

## SC-F-05 (MEDIUM) — UPGRADER_ROLE granted to admin w/o admin==timelock assert — OPEN
- `CealisSecurityMultisig.initialize` (governance/CealisSecurityMultisig.sol:60-78): line 72-73
  grants DEFAULT_ADMIN_ROLE + UPGRADER_ROLE to `admin`. `timelockController_` is stored
  separately (line 69). NO `require(admin == timelockController_)` anywhere.
- `EmergencyGovernance.initialize` (governance/EmergencyGovernance.sol:33-42): line 36-37
  grants DEFAULT_ADMIN_ROLE + UPGRADER_ROLE to `admin`. No timelock param even exists here;
  no assert.
- Deploy call sites: `script/Deploy.s.sol:339` passes `(admin=temporaryAdmin, timelock, ...)`;
  `:348` passes `(admin=temporaryAdmin, securityMultisig, ...)`. So at init the DEPLOYER
  (temporaryAdmin) holds UPGRADER on both governance contracts — not the timelock.
- Mitigation exists but is OUT-OF-CONTRACT and post-hoc: `PostDeploy._transferUUPSControl`
  (PostDeploy.s.sol:301-342) grants UPGRADER+DEFAULT_ADMIN to `addrs.timelock` (337-338) and
  revokes both from temporaryAdmin (339-340) for all 31 targets incl. securityMultisig (303) +
  emergencyGovernance (304). So end-state is correct, but the CONTRACT does not enforce the
  invariant — between Deploy and PostDeploy._transferUUPSControl the deployer can upgrade.
- Status OPEN (contract-level assertion absent). Severity MEDIUM. Coupled to the F-01
  test-fixture batch (May-14 plan line 112: "requires fixtures to pass actual timelock, not
  temporaryAdmin"). fix_location: add `if (admin != timelockController_) revert ...` in
  CealisSecurityMultisig.initialize; for EmergencyGovernance, add a timelock param + assert.

## F-01 (MEDIUM) — 30 upgradeable contracts missing _disableInitializers() — OPEN
- `grep -rn _disableInitializers src/` → ZERO hits. `grep -rn "constructor()" src/` → ZERO.
- 30 contracts declare `initialize`/`external initializer` (grep count = 30). None lock the impl.
- May-14 plan claimed "PATCHED — 22 files" but it was REVERTED (per the May-14 remediation plan,
  "Fix 1 (REVERTED)") — adding the constructor produced 67 forge `InvalidInitialization()`
  failures because tests deploy impls directly and call `.initialize()`.
- TEST-FIXTURE MIGRATION DID NOT HAPPEN: 29 test files still use direct-init (`new X(); x.initialize(...)`),
  e.g. test/registries/_HistoricalLookup.t.sol:50-76, test/disclosure/DisclosureRevocationRegistry.t.sol:21-22.
  Only 5 test files reference ERC1967Proxy, and those are upgrade-PATH tests
  (DisclosureRegistry.t.sol:156-160, PluginHash.t.sol:77-82), NOT a fixture-wide migration.
- Status OPEN. The naive fix (add constructor) still breaks 67 tests — do NOT propose it
  standalone. Real fix = migrate all direct-init fixtures to ERC1967Proxy first (1-2 day Phase B
  per plan), THEN add `constructor() { _disableInitializers(); }` to the 30 impls. fix_location:
  src/**/*.sol impl constructors + test fixture migration.

## BR-A (architectural) — G4 Phase-1 software signing key extractable from host — ARCHITECTURAL-ACCEPTED
- G4 Phase-1 is an explicit software scaffold: `v3-api/src/g4/sealed-code-server.ts:16-32`
  header "⚠️ TEE STUB — NOT PRODUCTION-SAFE (Decision D9)"; DEK generated in ordinary Node
  process memory (line 33), hard `NODE_ENV==="production"` guard throws (27-31).
- `v3-custody/src/g4-phase1/mtls-https-transport.ts:3` — "Railway-hosted (or future Nitro
  Enclave) G4 daemon"; the signing private key referenced (line 40) is the orchestrator mTLS
  client key, not a TEE-sealed authority key.
- This is the designed `G4Phase.Phase1 → Phase2` boundary (PostDeploy registers both phases,
  :160-194). Phase-2 rented TEE is the documented mitigation (project design constraints §0; G4 Phase-2 binding
  + dcap verifier at PostDeploy:177-193). Not a code defect — accepted architectural posture
  gated by the production guard. Status ARCHITECTURAL-ACCEPTED.

## F-03 — caret semver on noble deps in v3-crypto vs exact-pin elsewhere — FIXED
- `v3-crypto/package.json:36-39` — all EXACT: @noble/hashes 1.8.0, @noble/curves 1.9.7,
  @noble/ciphers 1.3.0, @noble/post-quantum 0.5.4. No caret.
- Sweep across all the packages package.json (excl. node_modules + vendored lib/): ZERO caret/tilde
  on any @noble dep in Cealis-authored packages. The only `^2.0.1` is in
  contracts/lib/openzeppelin-contracts/package.json — a vendored OZ submodule, not Cealis-authored.
- Status FIXED. The v3-crypto/elsewhere divergence the finding named no longer exists.

## F-04 — dual @noble/curves versions (1.9.7 direct + 2.0.1 transitive) — OPEN (LOW)
- pnpm-lock.yaml resolves FOUR distinct @noble/curves: 1.7.0, 1.8.0, 1.9.7, 2.0.1
  (lock lines 1077-1089 / 5002-5014).
- 1.9.7 = Cealis direct (crypto core). 2.0.1 = transitive via @noble/post-quantum@0.5.4
  (lock 5028-5031: pq 0.5.4 → curves 2.0.1 + hashes 2.0.1). So even with the exact direct
  pin, pq pulls its own curves 2.0.1 → the 1.9.7/2.0.1 coexistence the finding named is REAL.
- 1.7.0 (via @scure/bip32, lock ~5273) + 1.8.0 (via @walletconnect/relay-auth, lock ~5741)
  are deeper wallet-tooling transitives — not security-core.
- Status OPEN as a dependency-hygiene finding. LOW severity: the skew is transitive, each
  consumer uses its own pinned copy, no version-confusion attack surface in Cealis crypto paths
  (v3-crypto imports the direct 1.9.7). fix_location: optional pnpm `overrides`/dedupe to collapse
  curves to a single line where possible, or accept the pq-2.0.1 split as unavoidable until
  @noble/post-quantum aligns to curves 1.x. Not blocking.
