# Vault operator transition (§14.3, Ceremony 16)

**Spec:** S2-6 §14.3
**Authority:** TimelockController (planned 7-day) OR EmergencyGovernance + CealisSecurityMultisig (emergency read-halt).
**Governance path:** `timelock-7d-addition` for planned; `instant-non-canonical-deprecation` for emergency read-halt.
**Expected on-chain events:** `VaultTransitionQueued`, `VaultTransitionFinalized` (logical mapping per §18).
**Failure modes:** `TRIPWIRE_BYPASS` (identical source + destination audit-log roots — implies no migration manifest binding).

> Moves sealed ciphertext, σ_subject storage, metadata, and append-only audit logs to successor storage. `h_commit` does NOT change. Retention floors and shred obligations survive migration.

## NORMATIVE invariants

- **Audit-log root continuity** (§14.3): destination root commits to FULL source audit-log root + migration manifest (NOT truncated replay). Identical source/destination audit-log roots → fail-closed `TRIPWIRE_BYPASS` (implies missing manifest binding).
- **Carry-forward state**: retention floors, legal holds, active pauses, pending shreds, finalized shreds, and deletion proofs survive migration as state roots.
- **Event surface**: logical `VaultTransitionQueued` / `VaultTransitionFinalized` per §18.

## Authority dispatch

- **Planned transition** (operator migration, infra refresh): 7-day TimelockController. `emergencyReadHalt = false`.
- **Emergency read-halt** (current vault operator compromised): immediate halt via EmergencyGovernance + CealisSecurityMultisig. Replacement storage activation STILL requires either a pre-staged destination OR standard 7-day activation. `emergencyReadHalt = true`.

## Prerequisites

- `sourceVaultRoot` + `destinationVaultRoot` computed off-chain (Merkle root of vault state).
- `sourceAuditLogRoot` + `destinationAuditLogRoot` (append-only audit log Merkle roots). Destination commits to source + migration manifest.
- `retentionStateRoot` + `shredStateRoot` (carry-forward Merkle roots).
- `migrationManifestHash` (manifest CID hash binding the transition's bookkeeping).
- `rollbackBound` (block number beyond which rollback is no longer permitted).
- `notificationHash` (partner/subject notification CID hash).
- Dry-run checksum comparison successful (S3-1 migration logistics).
- For emergency path: source operator access revocation prepared.

## Step 1 — Proposal

Payload:
- `sourceVaultRoot`, `destinationVaultRoot`
- `sourceAuditLogRoot`, `destinationAuditLogRoot`
- `retentionStateRoot`, `shredStateRoot`
- `migrationManifestHash`
- `rollbackBound`
- `notificationHash`
- `emergencyReadHalt` (boolean)

Construct-time check: identical source + destination audit-log roots → `CEREMONY_ERR_TRIPWIRE_BYPASS`.

## Step 2 — Queue

`TimelockController.schedule(...)` with delay = 7 days (planned) OR 0 (emergency read-halt). Emit `VaultTransitionQueued`.

## Step 3 — Observation

Partners receive notification (CID published; CID-hash in proposal metadata). Dry-run checksum comparison validates source → destination state mapping. Rollback drills exercised in S3-1.

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits `VaultTransitionFinalized`.

## Step 5 — Verify

- Both `VaultTransitionQueued` and `VaultTransitionFinalized` observed.
- Destination vault root resolves on chain.
- Destination audit-log root verifies source-+-manifest binding (off-chain audit step).
- Retention + shred state carried forward via `retentionStateRoot` + `shredStateRoot`.
- All ciphertext + σ_subject + metadata accessible on destination vault.
- `h_commit` UNCHANGED — historical commits still verify.

## Abort discipline

A failure leaves the source vault canonical. Migration manifest archived for re-attempt. Rollback path engages if execute partially fails before `rollbackBound`.

## S3-1 ownership

S3-1 owns:
- migration logistics,
- dry-run checksum comparison,
- rollback drills,
- operator access revocation,
- partner-visible migration notices.

S2-6 fixes that vault operator transition preserves `h_commit`, audit-log root continuity, retention + shred state carry-forward, and does NOT change content.

## Cross-references

- WP §M (vault storage).
- S2-2 §10 (ShredRegistry carry-forward surface).
- legal Art. 5(1)(e) GDPR + §195 BGB retention floors.
