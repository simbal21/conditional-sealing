# G4 binary-hash registry update (§3, Phase 1 only)

**Spec:** S2-6 §3
**Authority:** Registry admin proposes; TimelockController executes.
**On-chain role:** `REGISTRY_ADMIN_ROLE`.
**Governance path:** `timelock-7d-addition` (additions); `expedited-24h-canonical-in-use-deprecation` + `instant-non-canonical-deprecation` for compromise.
**Expected on-chain events:** `EntryAdded` (and `DeprecationFlagSet` + `DisclosurePublished` on disaster path).
**Failure modes:** reproducibility mismatch, registry collision, timelock expiry, phase-ineligible PDA, tombstone conflict.

> Phase 1 is dev-scaffold only. Observed partner-facing Phase 1 use is severity critical.

## Prerequisites

- Reproducible-build artefacts: source commit digest, binary hash, build environment digest, test vector digest, metadata hash.
- `effective_block` chosen (must be after `currentBlock + 7 days` worth of blocks).
- S2-3 adapter compatibility verified.
- Vetting digest archived under CID; CID hash included in proposal metadata.

## Step 1 — Proposal

Build the proposal packet:
- `phase = 1`
- `g4_authority_ref` (new entry ref)
- `binary_hash`
- `source_commit_digest`
- `build_env_digest`
- `test_vector_digest`
- `metadata_hash`
- `effective_block`

Compute deterministic proposal hash via `proposalHash(payload)`.

## Step 2 — Queue

Submit `TimelockController.schedule(target=G4AuthorityRegistry, data=addEntry(...), predecessor=0x0, salt, delay=7d)`. Record the returned op id.

## Step 3 — Observation (7 days)

Security review verifies:
- binary reproducibility,
- source/hash match,
- no PII logging surface,
- S2-3 adapter compatibility,
- no canonical-in-use conflict on the same `g4_authority_ref`.

## Step 4 — Execute

After the 7-day delay, submit `TimelockController.execute(...)` with identical args. Confirm receipt emits `EntryAdded`.

## Step 5 — Verify

- New entry visible via `getEntryAt(g4_authority_ref, effective_block)`.
- Deprecation flag NOT set on the new entry.
- Old entry remains valid for historical commits per §3.5.
- Audit log written to `logs/g4-binary-hash-update-<ts>.log` contains the proposal hash and emitted event names; PII allow-list violations would have aborted at log emission.

## Abort discipline (§20)

A failure between steps 1–4 leaves the old canonical entry in effect. The abort path records the proposal hash, failure reason code, and block context in the log. If the timelock op is queued but not yet executed, call `TimelockController.cancel(opId)` to retire the queued state.

## Disaster path (§3.7)

If the canonical Phase 1 binary is compromised:
1. CealisSecurityMultisig submits `setDeprecationFlag(g4_authority_ref, reasonCode=0x06)` via Safe execTransaction.
2. If canonical-in-use: 24h expedited delay AND `publishDisclosure(bytes)` within 72h (reason + summary, no PII). Missing disclosure → permissionless `triggerAutoClear(entry_id)` after 72h + 30-day cooldown.
3. If non-canonical: instant deprecation by CealisSecurityMultisig, disclosure still within 72h.
4. Replacement binary follows the standard 7-day addition unless a pre-queued standby exists.

## Cross-references

- S2-1 §9, §11 (σ_G4 + endpoint attestation), §12 (G4AuthorityRegistry verification).
- S2-2 §9.6 (contract entry shape).
- S2-3 §7 (adapter behavior).
