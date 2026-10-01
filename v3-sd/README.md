# @cealis/v3-sd

## Status (at retirement, June 2026)

**partial.** Honest work-in-progress; not a finished pipeline.

Cealis V3 Selective Disclosure pipeline per `docs/specs/sd-spec-v2.md` (S2-7).

## Status

**Phase A (foundations + scaffolding) — 2026-05-13.**

Phase A ships:

- TAG_SD_*_V3 catalog (12 entries, RETIRED `TAG_SD_REVOCATION_V3` negative-tested)
- ERR_SD_* error catalog (16 codes) + SafeRefs allow-list + `SdError` class
- App. I 11 normative data structures (TS type declarations)
- App. M wording-lint catalog + script
- §7.9 constraint-budget catalog
- §15.2 7-row failure-mode table
- M1 (`@cealis/v3-crypto`) facade with §15 one-way edge discipline
- M2 ABI facade (loads `DisclosureRegistry` + `DisclosureRevocationRegistry`
  from Foundry artifacts)
- Asymmetric-isolation boundary type catalog
- Mode B + SD `assertModeBSdCompatible` guard (two-branch coverage)
- M5 ingestion stub interface (Phase B fills body, Phase E re-uses)
- M2 storage-layout baseline snapshot
- 22 Phase A items per PHASE-PLAN §A; 16 foundation tests

Phase B/C/D/E fill bodies. See `SPEC-COMPLIANCE-GUARD-M6.md` for the locked
anti-drift contract.

**Update at retirement (June 2026).** The Phase A list above is historical.
Later phases delivered the bodies: the prover (`src/prove/`), Merkle
(`src/merkle/`) and Mode B (`src/mode-b/`) implementations, the circuits,
and the locked test-vector set (`test-vectors/`, vectors 01–16); the `sdk/`
subpackage runs 23/23 green. What never happened is the wiring — this
package remains real cryptography that the API never calls, which is the
"not wired into the API" status in the root README's table.

## Subpackage

`sdk/` ships `@cealis/v3-sd-verify` — INDEPENDENT partner verification SDK
(§9.5 normative; zero workspace deps on Cealis runtime).

## Compliance

See [`SPEC-COMPLIANCE-GUARD-M6.md`](./SPEC-COMPLIANCE-GUARD-M6.md) for the
25-section anti-drift contract that binds Phase B/C/D/E.

## License

Apache-2.0 (see the repository root `LICENSE`).
