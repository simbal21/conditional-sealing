# Getting started (local dev)

Status: archived reference implementation — see the "Read this first" note and the "What this is not" section in the README.

This guide gets you from clone to green tests, with one caveat up front about
what "green" means in an archive.

## Prerequisites

- **Node.js >= 20**
- **pnpm >= 9** (the workspace pins `pnpm@9.15.0`)
- **Foundry** (`forge`) for the Solidity workspace — install via `foundryup`

## Install and run the suites

From the repository root:

```bash
pnpm install
pnpm -r run build       # build first: workspace packages resolve each other
                        # through compiled dist/ entry points, so typecheck
                        # fails without it (CI does the same)
pnpm -r run typecheck

# Expected-green subset — mirrors CI. v3-sd and v3-demo need extra toolchain
# steps (circom/PLONK setup, forge build artifacts) explained below:
pnpm -r --filter '!@cealis/v3-sd' --filter '!@cealis/v3-sd-verify' --filter '!@cealis/v3-demo' run test
```

Contracts (Foundry):

```bash
cd contracts
forge test    # vendored forge-std + openzeppelin in contracts/lib — no forge install needed
```

## Green at retirement, not guaranteed green today

All of the above was green at retirement in June 2026: the contract and
TypeScript suites passed in full. But an archive does not get dependency maintenance, and
a fresh install months or years later can break on toolchain or dependency
drift that has nothing to do with the code.

**Verification status — last real run of these exact commands:**

> **Verified 2026-07-03** (Node 26.4, pnpm 10.32, forge 1.7.1, macOS):
> `pnpm install` and `pnpm -r run build` succeed. Test results, honestly:
>
> - **Fully green:** `v3-crypto` **153/153** (the golden fixtures), `v3-configurator`
>   **440/440**, `v3-custody` **191** passed, `v3-ops` **218/218**, `verify-sdk` **102/102**,
>   `v3-sd/sdk` **23/23** — all passing on a fresh install.
> - **Toolchain preconditions, not rot:** `v3-sd`'s 15 failing integration tests need
>   `pnpm run setup:circuits` (circom/PLONK setup) first, and `v3-demo`'s ABI tests need
>   `forge build` artifacts from `contracts/` — install Foundry and build before judging these.
> - **`v3-api` needs the contract build too:** its tests load the compiled
>   `ConditionEngine` ABI from `contracts/out/`. Without `forge build` first, 23 of its
>   tests fail on the missing artifact (the 2026-07-03 run misread this as dependency
>   drift). Re-checked 2026-09-30 on Node 26 / forge 1.7.1: after `forge build` in
>   `contracts/`, `v3-api` passes in full (66 environment-gated tests skipped).
> - **Solidity suite reproduced exactly:** `forge test` in `contracts/` on the same
>   date — **330 passed, 0 failed, 0 skipped** (forge 1.7.1, solc
>   0.8.28), matching the retirement count. Note: `contracts/lib/` ships vendored
>   copies of forge-std and openzeppelin-contracts at the commits the project
>   pinned, so no submodule or `forge install` step is needed.

If something fails for you, assume drift first (Node/pnpm/Foundry versions,
transitive dependencies), and check the pinned versions in each workspace's
`package.json` and in `contracts/foundry.toml` / `foundry.lock`.

## What to try first

### 1. The golden fixtures in `v3-crypto` (fastest "see it work" path)

`v3-crypto` is the strongest part of the codebase, and its test suite runs the
primitives against 16 locked golden fixture files in `v3-crypto/test/fixtures/`
(AEAD, Shamir positive/negative, hybrid post-quantum wrap, envelope, stanza
MACs, the σ signature verifiers). These are byte-exact fixtures, so a pass
means the crypto reproduces the spec's expected outputs exactly:

```bash
pnpm --filter @cealis/v3-crypto test
```

### 2. The `v3-demo` rounds (illustrative end-to-end, mocked)

`v3-demo` wires the whole stack into four scripted rounds (escrow happy path,
shred via absence-of-event, a G4 mid-flight refusal, selective disclosure).
Be clear about what it is: **illustrative only** — at retirement it ran against
in-memory mocks and stubbed gate transports, so it demonstrates the intended
flow, not a working production system. It is also not one-command: CI mode
needs a local Anvil fork plus Postgres, Redis, a G4 mock, and a set of
contract-address environment variables. The real commands (from
`v3-demo/README.md`) look like:

```bash
# from v3-demo/, after pnpm -r run build, with the env described in its README
DEMO_MODE=ci-anvil pnpm exec demo round1
```

Read `v3-demo/README.md` for the full environment list, the round table, and
the current status: all four rounds are implemented and wired into the CLI
dispatch, executing against in-process synthetic adapters (a mocked chain
anchor, synthetic gate signatures) — the live Anvil-fork integration never
shipped. A passing round demonstrates the composed flow over mocks; it is not
evidence of a live system.

### 3. Do not point anything at the live testnet contracts

The Base Sepolia deployment is a historical proof-of-deployment only. The
deployed bytecode predates later source-level security fixes, and you should
never send value to those contracts. Full disclaimer: `deployments/README.md`.

## Where to go next

README → `docs/audits/MATURITY-SCORECARD.md` (the maturity self-assessment) →
`WHITEPAPER.md` (the readable design edition; full specs in `docs/specs/`) →
`v3-crypto/` (the strongest code).
