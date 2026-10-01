# Re-key / stanza-addition (§8, P21)

**Spec:** S2-6 §8 + §8.10
**Authority:** RekeyGovernance multisig; TimelockController writes after delay.
**On-chain role:** `REKEY_GOVERNANCE_ROLE`.
**Governance path:** `timelock-7d-addition`.
**Expected on-chain events:** `CommitSuperseded`.
**Failure modes:** unauthorized RekeyGovernance, missing recipient participation, `commit_AAD_vN`/`h_commit_vN` mismatch, supersession lineage break, generation overflow, share zeroization failure.

> Re-key is ADDITIVE at the stanza layer. It does NOT touch payload bytes, regenerate DEK, mutate the original `h_commit`, or treat σ as entropy. It preserves Shamir share values and `file_key` across generations.

## Prerequisites

- Cryptanalytic / vendor / TEE / SDK trigger documented (§8.2).
- Affected commits batched. Generation `N` chosen.
- New primitive generation specified.
- Client-support requirements documented (combiner SDK min version).
- Recipient-participation adapter (`RecipientParticipationAdapter`) configured. M7 ships the interface stub; S3-1 wires the UX flow for Mode 1 PASSKEY_ACCOUNT and Mode 2 WALLET_EOA. Mode 3 reserved at V2 launch.

## Step 1 — Proposal

Build `commit_AAD_vN` per §8.5:
- prior canonical AAD
- `superseded_commit_ref = oldHCommit`
- `commit_generation = N`

Compute `h_commit_vN = keccak256(commit_AAD_vN || post-re-key envelope hash)`.

Proposal payload includes: `oldHCommit`, `commitGenerationN`, `newHCommit (= h_commit_vN)`, `lineageRoot`, recipient set.

## Step 2 — Queue

`TimelockController.schedule(target=SupersededCommitRegistry, data=addEntry(oldHCommit, newHCommit, generation=N), delay=7d)`. Recipients + auditors inspect parameters during the window.

## Step 3 — Observation (7 days)

Recipients prepare to participate (Mode 1 / Mode 2). Auditors verify lineage continuity (`superseded_commit_ref` points at the prior generation's `h_commit`).

## Step 4 — Execute

§8.4 fresh σ collection happens inside the hardened combiner context:
- Lit, G3, G4, and configured conditional-recipient threshold participants produce fresh σ over the existing lineage root context under the newer primitive or authority generation.
- G1 chain authorization remains the predefined on-chain condition — re-key does NOT create a release event without G1.
- σ values cross the re-key boundary ONLY inside the hardened gate-adapter/combiner context. No retry queue, log, crash dump, diagnostic artifact, or audit event contains σ bytes, share bytes, DEK, or plaintext.

The ceremony calls `recipientParticipationAdapter.collectFreshSigma(...)` which returns ONLY public participation evidence (recipient pubkey + ack digest). The σ values themselves never leak through the interface.

After ack digests are collected, submit `TimelockController.execute(...)`. Receipt emits `CommitSuperseded { oldHCommit, newHCommit, generation: N }`.

## Step 5 — Verify

- SupersededCommitRegistry maps `oldHCommit → newHCommit` with `commit_generation = N` at the new effective block.
- Original envelope remains recoverable until governance-deprecated (§8.7).
- `commit_AAD_vN` and `h_commit_vN` reconcile when recomputed from the audit log.
- Combiner SDK can walk the supersession chain back to the original `h_commit` per §8.6.

## §8.6 Combiner recovery

Recipient combiner walks SupersededCommitRegistry to the selected generation, verifies that generation's σ values and registry state, decaps Shamir shares from that same generation, and reconstructs the same DEK. AEAD verification MUST use the selected generation's `commit_AAD_vN` as additional authenticated data; using original-generation AAD against generation-N envelope state is invalid. Default implementation uses one generation's stanza set per recovery for audit simplicity.

## §8.7 Old-stanza deprecation

A separate governance deprecation triggers after:
- new generation lives for the grace period,
- risk register justifies retirement,
- recipient migration drops below threshold,
- SDKs have upgrade support.

Deprecation is an operational gate; it does NOT delete historical envelope bytes.

## Abort discipline (§20)

A failed re-key leaves original commitment valid (§20.2). The abort path records proposal hash, generation, lineage root, failure reason. If the timelock op is queued but unexecuted, `TimelockController.cancel(opId)` retires the queued state.

## Cross-references

- S2-1 §15 (re-key cryptographic invariants).
- S2-2 §16 `REKEY_GOVERNANCE_ROLE` + SupersededCommitRegistry.
- S2-3 §11 (version pins).
- WP §M (crypto-aging).
