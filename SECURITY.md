# Security

## Status of this repository

Conditional Sealing is an **archived reference implementation**, retired in June 2026. It is
not maintained, not monitored, and **must not be used in production**.

- The codebase was **never independently audited.** Internal adversarial
  security reviews exist under `docs/audits/` and are published for
  transparency; they are not a substitute for an external audit.
- The deployed contracts referenced in `deployments/` live on **Base Sepolia
  (testnet) only** and may lag or diverge from the source in this repository
  (see the drift disclaimer in `deployments/README.md`).
- No real user data was ever processed by this system.
- **No real value, ever.** Do not use this code — or any fork of it — with
  real funds, real assets, or real personal data. The contracts and
  cryptographic code carry known, documented vulnerabilities (see
  `docs/audits/FINDING-RECONCILIATION.md`) that will never be fixed in this
  repository.
- **Archived means unmaintained.** No security fixes, advisories, or patches
  will be issued for this repository after archiving. Vulnerabilities
  reported later are read on a best-effort basis (see below) and will not
  result in code changes here.
- There is no bug bounty.

## Reporting

This repository is archived intentionally, and GitHub disables private
vulnerability reporting on archived repositories, so there is no advisory
inbox here. If you find a vulnerability that you believe endangers someone
actively using a fork of this code, email **simon@simonbaltes.com**. Reports
are read on a best-effort basis with no SLA and no guaranteed response.

## If you fork this

Treat every cryptographic claim as unverified until you have audited it
yourself. Starting points: `docs/audits/MATURITY-SCORECARD.md` and
`docs/audits/honest-audit-2026-06-03.md`.
