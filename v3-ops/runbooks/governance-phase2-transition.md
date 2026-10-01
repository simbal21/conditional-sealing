# Governance Phase 2 transition (§16.5)

**Spec:** S2-6 §16.5 + §16.3
**Authority:** TimelockController + external advisors.
**On-chain role:** role grants for governance seats.
**Governance path:** `timelock-7d-addition`.
**Expected on-chain events:** `RoleGranted`, `GovernancePostureAnnounced` (+ `RoleRevoked` if member removals).
**Failure modes:** `QUORUM_MISSING` (multisig actors collapsed), `REGISTRY_COLLISION` (missing role-grant event), `TRIPWIRE_BYPASS` (governance changes attempt to grant reveal).

> §16.3 NORMATIVE deadline: external advisor seats complete BEFORE first paying partner OR within 90 days of V2 launch, whichever sooner. Partner onboarding HALTS if the §16.3 verification gate fails.

## §16.3 NORMATIVE pre-check

Before accepting the first paying partner (`partnerRegistered` event on PartnerRegistry) AND before any new partner onboarding after day 90, operations MUST verify:
1. external-advisor seating proof present (`advisorSeatProofHash`),
2. role-grant events on chain (`roleGrantEventsObserved`),
3. governance posture announcement hash verifies (`postureAnnouncementHash`).

If verification fails → partner onboarding halts. The `checkPhase2VerificationGate()` helper exposes the same logic for M5 partner registration code paths and Phase F integration tests.

## §16.4 public-copy discipline (sensitive)

> public-copy-sensitive.

Any material invoking emergency governance during Phase 1 MUST name current AND target posture. It may say halt is on-chain-visible and process-gated. It MAY NOT imply independent-domain defense before external seats exist.

## Prerequisites

- External-advisor candidates identified, key-control proven (off-chain). Each candidate signs an attestation digest archived under CID; the CID-hash is the `advisor_seat_proof_hash`.
- Member-role metadata hash committed off-chain (member name digest, role assignment, jurisdiction, term length where applicable).
- Governance posture announcement drafted with current vs target posture. CID published; CID-hash = `posture_announcement_hash`.
- §1.1 invariant: `CealisSecurityMultisig` and `EmergencyGovernance` are SEPARATE Safe instances. The ceremony rejects identical addresses at construct time.

## Step 1 — Proposal

Payload fields:
- `cealisSecurityMultisigAddress` (distinct from `emergencyGovernanceMultisigAddress`)
- `emergencyGovernanceMultisigAddress`
- `memberAdditions[] = { address, roleId }`
- `memberRemovals[] = { address, roleId }`
- `memberRoleMetadataHash`
- `advisorSeatProofHash`
- `postureAnnouncementHash`
- `v2LaunchBlock`
- `transitionEffectiveBlock`

## Step 2 — Queue

`TimelockController.schedule(target=CealisSecurityMultisig, data=batchedRoleGrants+Revokes+postureAnnouncement, delay=7d)`.

## Step 3 — Observation (7 days)

External advisor candidates publicly acknowledge their seating. Counsel verifies key-control attestation. Partner-facing channels publish current-vs-target posture announcement (per §16.4 discipline).

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits:
- `RoleGranted` for each member in `memberAdditions`,
- `RoleRevoked` for each member in `memberRemovals` (if any),
- `GovernancePostureAnnounced` carrying `posture_announcement_hash`.

Existing deprecation flags remain valid; authority composition changes future governance actions only.

## Step 5 — Verify

- All expected events emitted (`RoleGranted` AND `GovernancePostureAnnounced` mandatory; `RoleRevoked` if any removals).
- `checkPhase2VerificationGate({ advisorSeatProofHash, roleGrantEventsObserved: true, postureAnnouncementHash, daysSinceV2Launch, hasPaidPartnerYet })` returns `null` (gate passes).
- M5 partner registration pre-check now resolves true → first `partnerRegistered` event unblocked.

## Abort discipline (§20)

A failure leaves Phase 1 governance posture in place. Cancel queued op via `TimelockController.cancel(opId)`. If the abort happens AFTER day 90 and BEFORE first paying partner: partner onboarding remains halted until a successful transition.

## Cross-references

- WP §N (Governance Phase 1/2 honest posture).
- S2-2 §16.5 (governance Phase 2 role-grant surface).
