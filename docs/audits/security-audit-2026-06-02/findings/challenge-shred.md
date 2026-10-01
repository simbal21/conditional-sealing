> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

_Base Sepolia deployment note: testnet only; deployed bytecode may lag or diverge from this source. See deployments/README.md._

# Audit reconciliation — challenge/ + shred/ — HEAD e87c108 (2026-06-02)

Read-only. Verdicts are grep/read against HEAD, not old finding text (Rule 45).
Files: `contracts/src/challenge/ChallengeRegistry.sol` (last touched May 14),
`contracts/src/shred/ShredRegistry.sol` (last touched May 14).
ChallengeRegistry is LIVE on Base Sepolia: `0x5f20AB2A915d4E218E0f59041A8c22Fd9449358d`
(`contracts/deployments/base-sepolia.json:3`).

---

## C2 — eligibleChallengersRoot merkle allowlist NOT enforced — STATUS: OPEN (CRITICAL, LIVE)

`configureChallenge` stores `eligibleChallengersRoot` (ChallengeRegistry.sol:130, written to config:138).
NatSpec at lines 117-119 asserts: "eligibleChallengersRoot is the merkle root for
permissionless-but-allowlisted opening (the challenger MUST be in the merkle set)."

`openChallenge` signature (lines 146-152): `(authorizationId, axis, reason, counterAttestationRef, bondAmount)`.
- NO merkle-proof parameter.
- NO `MerkleProof` import (grep: only the OZ AccessControl/Initializable/UUPS/ReentrancyGuard imports).
- NO `verify(...)` / `MerkleProof.verifyCalldata` call anywhere in the file.
- The ONLY caller-gating in openChallenge is line 162: `if (config.eligibleCaller != address(0) && msg.sender != config.eligibleCaller)`.

Result: when `eligibleCaller == address(0)` (the permissionless path that `eligibleChallengersRoot`
exists to gate), ANY address can `openChallenge`. The configured merkle root is dead storage,
never read in any execution path. This is the system-locked-principle breach: a non-allowlisted
party can open a challenge and halt a reveal/shred ceremony for the configured window
(extendable up to maxExtensions). Permissionless challenge-open against the configured allowlist.

Live-contract caveat: exploitability depends on whether deployed PDAs configure
`eligibleCaller == address(0)` with a non-zero `eligibleChallengersRoot`. The code makes the
allowlist UNENFORCEABLE in all cases — the root cannot constrain anything as written.

FIX: add `bytes32[] calldata merkleProof` param to openChallenge; when
`config.eligibleChallengersRoot != bytes32(0)`, require
`MerkleProof.verifyCalldata(merkleProof, root, keccak256(abi.encodePacked(msg.sender)))`.
fix_location: ChallengeRegistry.sol openChallenge (146-186) + import OZ MerkleProof.
NOTE: openChallenge sig change is an ABI break on a live contract → UUPS upgrade required.

---

## B3-bond — bond permanently locked after resolver action — STATUS: OPEN (HIGH)

Bond escrow paths:
- Posted in `openChallenge` → `record.bond = msg.value` (line 180).
- Refunded ONLY in `withdrawChallenge` (line 245 `msg.sender.call{value: bond}`), which requires
  `record.status == Open` (line 235) and `msg.sender == record.challenger` (line 238).
- `_resolve` (267-280, reached by `confirmNoIntervention` and `haltCeremony`) sets a terminal
  status (ConfirmedNoIntervention / Halted) and NEVER touches `record.bond` — no refund, no
  slash-to-treasury, no payout.
- `ChallengeResolved` event (66-68) carries NO bond-distribution semantics.

Once a resolver acts, status leaves Open → `withdrawChallenge` reverts → the bond at `record.bond`
is stranded in the contract forever. There is NO sweep / rescue / recover / withdrawSlashed /
claimBond function (grep over all external/public fns: initialize, configureChallenge,
openChallenge, confirmNoIntervention, haltCeremony, extendChallenge, withdrawChallenge,
challengeStatus, challengeConfig — none recover a resolved bond). Genuine fund-lockup.

Severity HIGH not CRITICAL: requires honest resolver action; funds locked, not stealable. Affects
both honest challengers (ConfirmedNoIntervention with no refund) and bad-faith challengers (Halted
with no slash destination — the bond just disappears into the contract instead of being forfeited
to a treasury).

FIX: in `_resolve`, route `record.bond` per resolved status (refund to challenger on
ConfirmedNoIntervention; forfeit to a configured treasury/operator on Halted/Dismissed), zeroing
`record.bond` and following CEI. fix_location: ChallengeRegistry.sol `_resolve` (267-280).

---

## SC-F-07 — withdrawChallenge no reentrancy guard — STATUS: FIXED

`withdrawChallenge` at line 232 carries `nonReentrant` (contract inherits
`ReentrancyGuardTransient`, import line 7, in inheritance list line 27). Additionally CEI-compliant:
state writes (`record.status = Withdrawn` line 242, `record.bond = 0` line 243) precede the
external `.call` (line 245). Both guard AND ordering present. Old finding (~231-248) remediated.

---

## SC-F-03 — finalizeShred no reentrancy guard — STATUS: FIXED

`finalizeShred` at ShredRegistry.sol:161 carries `nonReentrant` (contract inherits
`ReentrancyGuardTransient`, import line 7, inheritance line 39). The only external call is the
trusted-contract callback `recordShredFinalized` (line 195) at the very end, after all state
writes (state=Finalized 182, proofShred 188, state=Shredded 192, _shredded[hCommit]=true 193).
Guard + CEI both present. Old finding (~160-194) remediated.

---

## B3-shred — ShredRegistry OPERATOR vs Timelock authority conflation — STATUS: PARTIAL (MEDIUM)

Two distinct sub-issues; both real, partially mitigated by deploy config.

(1) CONTRACT-LEVEL — `_validateAuthority` (219-232) conflates Joint with Operator:
   - `ShredAuthorityMode.Operator` (3): requires `OPERATOR_ROLE` (line 223).
   - `ShredAuthorityMode.Joint` (2): requires `OPERATOR_ROLE` ONLY (line 229) — IDENTICAL check.
     "Joint" is documented (lib/Enums.sol:58 + ShredRegistry NatSpec 25-29) as subject+operator
     co-consent, but on-chain it is satisfiable by a unilateral OPERATOR_ROLE holder. Joint
     provides ZERO additional authority over Operator. No subject-signature / dual-consent check.
   - `ShredAuthorityMode.Subject` (1): NO branch in _validateAuthority → passes for ANY caller
     (subject is off-chain/passkey, plausibly by design, but un-enforced at this layer).
   - `ShredAuthorityMode.Timelock` (4): requires `DEFAULT_ADMIN_ROLE` (line 226).

(2) INITIALIZE/DEPLOY-LEVEL — principal overlap:
   - `initialize()` grants BOTH `DEFAULT_ADMIN_ROLE` (line 74) AND `OPERATOR_ROLE` (line 77) to the
     same `timelock` arg. At deploy this arg = `temporaryAdmin` (Deploy.s.sol:302 prank context;
     PostDeploy.s.sol:65 `vm.startPrank(addrs.temporaryAdmin)`).
   - PostDeploy revokes DEFAULT_ADMIN + UPGRADER from temporaryAdmin on shredRegistry
     (PostDeploy.s.sol:339-340, shredRegistry in `targets` line 331). It does NOT revoke
     OPERATOR_ROLE from temporaryAdmin — no `_revokeIfHeld(shredRegistry, OPERATOR_ROLE, ...)`
     anywhere. The initialize-granted OPERATOR on the deployer EOA SURVIVES the handoff.
   - PostDeploy ALSO grants OPERATOR_ROLE to a separate `operator` EOA (line 251,
     `OPERATOR_ADDRESS` env, defaults to temporaryAdmin if unset).
   - Net: post-deploy, Operator-mode shred is satisfiable by {operator EOA, leftover deployer EOA};
     Timelock-mode by the real timelock. The roles ARE separable in intent (distinct EOAs when
     OPERATOR_ADDRESS set), so this is PARTIAL — the conflation is in the contract's Joint-mode
     logic + a residual deployer-EOA OPERATOR grant, not a hard collapse of operator==timelock.

Severity MEDIUM: Joint-mode under-enforcement weakens a PDA-selectable guarantee but does not by
itself enable an unauthorized shred beyond what Operator mode already allows; residual deployer
OPERATOR is a deployment-hygiene gap (extra OPERATOR holder), revocable via timelock post-deploy.

FIX:
 - Joint mode: enforce true dual-consent (require an off-chain subject signature / co-signer in
   addition to OPERATOR_ROLE) in `_validateAuthority`. fix_location: ShredRegistry.sol:229.
 - Deploy: add `_revokeIfHeld(addrs.shredRegistry, Roles.OPERATOR_ROLE, addrs.temporaryAdmin)` to
   PostDeploy after the operator EOA grant, OR stop granting OPERATOR in initialize and rely solely
   on PostDeploy. fix_location: script/PostDeploy.s.sol (~251) + ShredRegistry.sol initialize:77.
