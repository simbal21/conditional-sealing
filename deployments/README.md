# Deployments — Base Sepolia (testnet only)

`base-sepolia.json` records the addresses of the V3 contract stack (developed under the working name Cealis) deployed to
**Base Sepolia** on 2026-05-14: **32 live contracts**. Thirty of them sit behind UUPS proxies: the addresses in `base-sepolia.json` are the **proxies, which are not Sourcify-verified**; the **implementation contracts** behind them are **Sourcify-verified (exact_match)**, as are the two directly deployed contracts (`identifierHelpers`, `timelock`). `base-sepolia-verification.json` maps each proxy to its implementation address and verification status (checked 2026-09-30). `exact_match` binds the deployed bytecode to the *May-14 pre-fix source snapshot*, not to this repository's current source. It proves that snapshot deployed as written (including the C2 vulnerability that was fixed only in source afterwards); it says nothing about the security of the code. Verification is a deployability record, not a safety claim.
The file maps contract names to addresses; it contains no keys or secrets.
(`revealAuthorizedEmitter` is the zero address — a placeholder, never deployed.
`temporaryAdmin` and `timelock` are the deploy-time admin/governance addresses.)

The main public entry point is the **`conditionEngine`** UUPS proxy:
`0xb09a8300423CA3BD0E028bAB6A6245A248520D02` — the single contract surface that can
emit `RevealAuthorized`.

`contracts/deployments/e2e-anvil.json` is a local Anvil test fixture, not a live deployment.

## DRIFT DISCLAIMER — read before touching anything on-chain

**The deployed bytecode was deployed BEFORE the final source snapshot in this repository
and may lag or diverge from this source.** In particular, security fixes made in source
after 2026-05-14 (including the 2026-06-02 audit remediations) were **never deployed**.
Known example: the deployed `ChallengeRegistry` does not enforce the
`eligibleChallengersRoot` allowlist that the source in this repo enforces.

- This system was **never externally audited** — only internal adversarial review.
- **Testnet only.** There is no mainnet deployment.
- **Do not send value** to, or build on, these contracts.
- Verify any on-chain behavior against the deployed bytecode, not this source.
