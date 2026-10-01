# Contributing

Short version: please don't — fork instead.

Status: archived reference implementation — see the "Read this first" note and the
"What this is not" section in the README.

This repository is not maintained. I don't expect to review pull requests or
respond to issues, and there is no roadmap to contribute to. The code is
published as a reference and a record, not as a living project.

## Forking is encouraged

Everything here is yours to take under the published licenses:

- **Code:** Apache-2.0 (see `LICENSE` and `NOTICE`) — includes an explicit patent grant.
- **Documentation and specifications:** CC BY 4.0.

No permission needed, no attribution beyond what the licenses require.

## Before any real use of a fork

This codebase carries the caveats in the README and `SECURITY.md`, and is
self-graded at roughly 3.5/5 maturity (an earlier 5.00/5 self-grade was
withdrawn — see `docs/audits/MATURITY-SCORECARD.md`). At retirement the gate
signing transports were stubbed, the runtime ran on in-memory mocks, and
`verify-sdk` is a stub. A fork that intends real use must, at minimum:

1. Commission an independent external security audit of the contracts and the
   cryptographic core. Internal reviews under `docs/audits/` are a starting
   map, not a substitute.
2. Finish the operational layer: real gate transports, real persistence,
   real key ceremonies. `docs/audits/MATURITY-SCORECARD.md` and
   `docs/state-at-retirement/` show exactly what is missing.
3. Ignore the Base Sepolia deployment — it is testnet-only and its bytecode
   predates later source fixes (see `deployments/README.md`).

Security notes and reporting: `SECURITY.md`.
