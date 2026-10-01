# Vendor fixture directory

This tree holds **vendor-confirmation artifacts** captured during Codex Phase B/C/D runs. Each per-vendor subdirectory accumulates real test vectors used for regression + the `VENDOR_CONFIRMATION.md` published in Phase F per S2-3 §11.4.

The 6 §11.4 confirmation items map to subdirectories as follows:

| §11.4 item | Subdir | Fixture filename |
|---|---|---|
| `VENDOR_CONFIRMATION_LIT_CORE_API` | `lit/` | `assignment-fixture.json`, `acc-fixture.json` |
| `VENDOR_CONFIRMATION_LIT_BLS_VARIANT` | `lit/` | `sigma-vector.json` |
| `VENDOR_CONFIRMATION_DCIPHER_SDK` | `dcipher/` | `sdk-status.json` |
| `VENDOR_CONFIRMATION_DCIPHER_BLS_VARIANT` | `dcipher/` | `sigma-vector.json` |
| `VENDOR_CONFIRMATION_AUTOMATA_DCAP_CONTRACTS` | `g4-phase2/` | `dcap-quote-stub.json` |
| `VENDOR_CONFIRMATION_AUTOMATA_GO_DCAP_SDK` | `g4-phase2/` | `p256-chain-stub.json` |

Plus auxiliary fixtures used by adapter unit tests:

| Item | Subdir | Filename |
|---|---|---|
| Drand round-vector | `drand/` | `round-vector.json` |
| G4 Phase 1 ed25519 vector | `g4-phase1/` | `ed25519-vector.json`, `attestation-fixture.json` |
| Lit DCAP fixture | `lit/` | `dcap-fixture.json` |

## Fixture format (uniform)

Every fixture is a JSON file with this top-level shape:

```json
{
  "kind": "VENDOR_CONFIRMATION_LIT_BLS_VARIANT",
  "capturedAt": "2026-05-XX",
  "capturedBy": "M3 Phase C codex chunk",
  "vendorVersion": "lit-protocol/lit-node-client@7.3.0",
  "spec_section": "S2-3 §3.3 + S2-1 §7.4",
  "data": {
    "...": "..."
  },
  "notes": "..."
}
```

The `data` field is adapter-specific. Phase F's closeout script aggregates these into `v3-custody/VENDOR_CONFIRMATION.md` by reading every fixture file's `kind` + `data` summary.

## Phase A scope

Phase A only creates `.gitkeep` placeholders so the directory structure exists. Codex chunks B/C/D capture real fixtures during their runs.

## Status mapping for `VENDOR_CONFIRMATION_DCIPHER_*`

If dcipher SDK is unavailable at build time (build-time exclusion path per S2-3 §6.2), Phase B writes `dcipher/sdk-status.json` with:

```json
{
  "kind": "VENDOR_CONFIRMATION_DCIPHER_SDK",
  "status": "deferred — SDK not GA at build time",
  "drand_only_ships": true,
  "build_time_exclusion_active": true
}
```

Phase F reads this and includes the deferral in `VENDOR_CONFIRMATION.md`. dcipher deferral is NOT a mission failure — drand-only is a clean ship per the build-time-exclusion contract.
