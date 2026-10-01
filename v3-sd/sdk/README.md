# @cealis/v3-sd-verify

Cealis V3 Selective Disclosure partner verification SDK per `docs/specs/sd-spec-v2.md` §9.

## Status

**Phase E shipped — 2026-05-13.**

The package exposes:

- `verifySdBundle(input)` for partner-side bundle verification.
- `verifyClaim(input)` for expiry, revocation, public-input, and proof checks.
- `verifyCleartextField(input)` for explicit `cleartext_zk_opened` or
  `cleartext_attested` field checks.
- `verifyBindingMode(input)` for `commit_AAD` root-mode detection.
- `InMemoryRevocationRegistryClient` for local fixtures and partner tests.

## Trust assumptions

A partner accepting SD trusts:

- the G4/SD TEE attestation chain for correct execution and salt secrecy,
- the circuit/verifier registry for correct verification keys,
- the partner SDK implementation,
- the binding between SD artifacts and escrow commit,
- expiry/revocation checks being performed at decision time.

The SDK makes zero Cealis-controlled network calls during `verifySdBundle`.
Revocation reads use partner-controlled RPC. PLONK proofs verify against a
locally-held verification key or caller-supplied verifier object.

## License

Apache-2.0 (see the repository root `LICENSE`).
