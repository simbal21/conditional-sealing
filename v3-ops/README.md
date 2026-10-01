# @cealis/v3-ops

## Status (at retirement, June 2026)

**Illustrative only.** The runtime behind these ceremonies used in-memory mocks; nothing here ever ran against production infrastructure.

Cealis V3 operational ceremonies per `docs/specs/operational-ceremonies-spec.md` (S2-6).

**17 ceremonies** — 16 catalog rows + Governance Phase 2 transition (§16.5).
**19 CLI commands** — `cealis-ops <name> [--dry-run] [args...]`.
**Two distinct multisig actors** — `CealisSecurityMultisig` (SECURITY_COUNCIL_ROLE) and `EmergencyGovernance` (EMERGENCY_GOVERNANCE_ROLE), separate Safe instances per S2-6 §1.1.
**Five Cealis-governed V3 registries** — `PluginHashRegistry`, `G4AuthorityRegistry`, `DSLVersionRegistry`, `OracleRegistry`, `QTSPRegistry`.
**10 G4 refusal reason codes** in 3 classes (per-subject 0x01..0x05, class-wide 0x06..0x09, advisory 0x0A).
**Nine ceremony error classes** — `CEREMONY_ERR_*` per S2-6 §1.7. No custom names.

## Where the build stopped

The 17 ceremonies and 19 CLI commands above are implemented, and the suite was 218/218 green on the 2026-07-03 fresh-install verification. None of it ever ran against a live network — every transport here is simulated.

## Discipline

- **At-commit-block reading** (§1.3 NORMATIVE): every registry read goes through `readEntryAt(reader, ref, commitBlock)`. Current-head reads are non-conformant.
- **PII allow-list** (§0.9 + §1.5): positive allow-list applies in both prod logs and `--dry-run`. Anything off-list throws `CEREMONY_ERR_PII_IN_LOG`.
- **σ-as-authorization** (§0.3): σ is authorization evidence, not DEK material. No ceremony in this package ever holds σ bytes, Shamir shares, DEK, plaintext, or ciphertext.
- **Halt-only emergency response** (§13.8): governance can halt or extend; it cannot grant reveal.

## CLI

```bash
pnpm exec cealis-ops --help
pnpm exec cealis-ops g4-binary-hash-update --dry-run --ref 0xdeadbeef
```

All 19 commands are listed by `--help` and execute against the simulated transports (see "Where the build stopped" below).

## Files

- `src/errors/` — 9-class `CeremonyError` + `CeremonyErrorCode` enum.
- `src/types/` — `TombstoneTuple`, `G4RefusalCode`, `PauseAuthority`, `ShredAuthority`, `CeremonyContext`, `CeremonyEventName`.
- `src/catalog/` — `CEREMONY_CATALOG` (17 rows) + `FIVE_V3_REGISTRIES`.
- `src/logging/` — PII allow-list + `createLogger` with discipline enforcement.
- `src/registry/` — `readEntryAt`, `isValidAtBlock`, `V3_REGISTRY_METADATA`.
- `src/multisig/` — Safe builder + two distinct configs + TimelockController helper + 5 governance paths.
- `src/adapters/` — vault client + recipient participation interface stubs.
- `src/m2-imports.ts`, `m3-imports.ts`, `m4-imports.ts` — typed re-exports + lazy ABI loaders.
- `src/cli/` — `cealis-ops` parser + registry + bin.
- `runbooks/` — markdown runbooks (Phase E populates).
- `tests/foundation/` — 12 foundation tests covering all PHASE-PLAN §0 drift catches.
- `SPEC-COMPLIANCE-GUARD-M7.md` — anti-drift checklist.

## License

Apache-2.0 (see the repository root `LICENSE`).
