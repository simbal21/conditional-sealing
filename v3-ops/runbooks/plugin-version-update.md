# Plugin-version update and signed distribution (§5)

**Spec:** S2-6 §5
**Authority:** Registry admin + release signer; TimelockController executes.
**On-chain role:** `REGISTRY_ADMIN_ROLE`.
**Governance path:** `timelock-7d-addition` (additions); emergency deprecation paths apply on CVE.
**Expected on-chain events:** `EntryAdded` + signed manifest hash.
**Failure modes:** binary hash mismatch, semver/source mismatch, signed manifest mismatch, SDK unsupported, remote enablement attempted for a deprecated profile, deprecation disclosure missing.

> Rollback is NOT a mutable channel flip. It is either deprecate-current + activate-already-staged, OR queue-new-signed-binary through PluginHashRegistry. Disabled profiles are signed binary metadata, not remote feature flags. Remote enablement MUST NOT revive a deprecated profile or gate layout without a new signed binary AND a new PluginHashRegistry entry.

## Prerequisites

- Reproducible build of the candidate plugin from source commit + lockfile + build environment digest. Canonical binary hash.
- Semver/release digest. Dependency lock digest. Test vector digest.
- Signed distribution manifest with `plugin_version_digest`, supported commit profile list, supported gate tuple layouts, the build hash used for `plugin_version_digest`, disabled profile list, minimum combiner SDK version, supported `commit_version` range, stanza-generation support, rollout channel, and rollback policy.
- Signed binary + manifest published on an immutable distribution channel; manifest hash/CID included in proposal metadata.
- S2-3 version-pin impact reviewed.

## Step 1 — Proposal

Payload fields:
- `plugin_version_digest`
- `binary_hash`
- `source_commit_digest`
- `semver_digest`
- `build_env_digest`
- `lockfile_digest`
- `signed_manifest_hash`
- `test_vector_digest`
- `supported_profile_hash` / `disabled_profile_hash`
- `min_combiner_sdk_version`
- `supported_commit_version_range`
- `rollout_channel`
- `effective_block`

Compute deterministic proposal hash.

## Step 2 — Queue

`TimelockController.schedule(target=PluginHashRegistry, data=addEntry(...), delay=7d)`. Record op id.

## Step 3 — Observation (7 days)

Recipients build from source, compare hash to the queued PluginHashRegistry entry, verify manifest signatures. Watchdogs check S2-3 SDK compatibility against the queued `min_combiner_sdk_version`.

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits `EntryAdded` carrying the new `plugin_version_digest` AND the signed manifest hash.

## Step 5 — Verify

- `plugin_version_digest` resolves at `getEntryAt(plugin_version_digest, effective_block)` to the queued binary hash + manifest hash.
- No deprecation flag on the new entry.
- Manifest hash/CID is unchanged in proposal metadata.
- Historical commits keep their original plugin verification path — old entries continue verifying via `getEntryAt(..., old_commit_block)`.

## Abort discipline (§20)

A failure between steps 1–4 leaves the prior canonical plugin in effect. The abort path records the proposal hash, manifest hash, failure reason code, and block context. Queued op cancellable via `TimelockController.cancel(opId)`.

## Disaster path (§14.4)

CVE on a vulnerable plugin entry: `setDeprecationFlag(plugin_version_digest, reasonCode=0x06 plugin_deprecated)` via CealisSecurityMultisig. Replacement plugin follows §5 standard 7-day addition unless a pre-queued standby exists. Remote disable may add a block; it MUST NOT revive a deprecated profile.

## Cross-references

- S2-1 §12.2 (plugin registry verification).
- S2-2 §9.5 (PluginHashRegistry), §9.11 (registry addition workflow).
- S2-3 §11 (version pins).
- WP §M (plugin distribution).
