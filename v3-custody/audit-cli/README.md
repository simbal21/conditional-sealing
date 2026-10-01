# Cealis G4 audit-CLI

Standalone verifier for Cealis G4 refusal claims. **Hermetic** — Node stdlib + `@noble/curves/ed25519` only; no chain RPC, no filesystem state, no network calls. Safe to run on air-gapped audit workstations.

## What this proves

When the deployed G4 Phase 1 daemon receives a `POST /refuse` from the orchestrator, it produces an Ed25519-signed canonical-bytes envelope (138 bytes layout) and returns it alongside the response. This CLI verifies that envelope:

**"The daemon at the given authority pubkey signed these exact canonical bytes."**

Combined with on-chain `G4AuthorityRegistry.sol` (the canonical record of daemon authority pubkeys), this is the cryptographic primitive that closes the **fraud-by-refusal** attack vector: an orchestrator that submits a refusal to `G4RefusalRegistry` on-chain cannot fabricate a matching daemon-signed claim post-hoc (Ed25519 sigs are not forgeable without the private key).

## Audit workflow

1. **Fetch the orchestrator's stored refusal claims** (off-chain log).
2. **Read the daemon's authority pubkey** from `G4AuthorityRegistry.sol` (Base Sepolia testnet only — the deployed bytecode may lag or diverge from this source snapshot; see `deployments/README.md`. No mainnet deployment exists.) at the claim's `authorization_block`.
3. **For each claim**, run:
   ```bash
   node verify-refusal-claim.mjs \
       --pubkey-hex 0x<32-byte-pubkey-hex> \
       --claim-file <claim.json>
   ```
4. **Cross-reference** against on-chain `G4RefusalRegistry` events for the same `authorizationId`. A refusal on-chain without a matching verified claim = orchestrator wrote unilaterally (audit-failure event).

## Usage

```bash
# By hex pubkey + file
node verify-refusal-claim.mjs --pubkey-hex 0xabc...def --claim-file claim.json

# By PEM pubkey + stdin
node verify-refusal-claim.mjs --pubkey-pem signing.pub < claim.json
```

### Input format

The CLI accepts both wrapped and flat shapes:

```json
{
  "refusalClaim": {
    "canonicalBytes": "0x<138-byte-hex>",
    "ed25519Sig":     "0x<64-byte-hex>",
    "domainLabel":    "CEALIS_V3_G4_REFUSAL_CLAIM_V1"
  }
}
```

```json
{
  "canonicalBytes": "0x...",
  "ed25519Sig":     "0x...",
  "domainLabel":    "CEALIS_V3_G4_REFUSAL_CLAIM_V1"
}
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Verified; parsed fields on stdout |
| 1    | Verification failed; typed error code + detail on stderr |
| 2    | Usage error |

### Output (verified)

```json
{
  "ok": true,
  "verified": "the daemon at this authority pubkey signed these exact canonical bytes",
  "parsed": {
    "authorizationId":       "0x1111...1111",
    "hCommit":               "0x2222...2222",
    "reasonCode":            6,
    "reasonName":            "PLUGIN_DEPRECATED",
    "encryptedReasonPresent": false,
    "encryptedBlobHash":     null,
    "timestamp":             "1716183600",
    "timestamp_iso":         "2024-05-20T05:00:00.000Z"
  },
  "domainLabel": "CEALIS_V3_G4_REFUSAL_CLAIM_V1"
}
```

### Output (failed)

```json
{
  "ok": false,
  "error": "ERR_CLAIM_SIG_VERIFY",
  "detail": "Ed25519 signature does not verify against authority pubkey"
}
```

## Error codes (7 typed)

| Code | Meaning |
|------|---------|
| `ERR_CLAIM_CANONICAL_LEN`         | canonical bytes ≠ 138 |
| `ERR_CLAIM_SIG_LEN`               | Ed25519 signature ≠ 64 bytes |
| `ERR_CLAIM_AUTHORITY_PUBKEY_LEN`  | authority pubkey ≠ 32 raw Ed25519 bytes |
| `ERR_CLAIM_DOMAIN_TAG_MISMATCH`   | first 32 bytes ≠ SHA-256("CEALIS_V3_G4_REFUSAL_CLAIM_V1") |
| `ERR_CLAIM_REASON_OUT_OF_RANGE`   | reasonCode outside [0x01..0x0A] |
| `ERR_CLAIM_ENC_PRESENT_INVALID`   | encryptedReasonPresent byte ≠ 0x00 or 0x01 |
| `ERR_CLAIM_SIG_VERIFY`            | Ed25519 verification rejected the signature |

## Reason codes (10, per G4RefusalRegistry.sol)

| Code | Name | Type |
|------|------|------|
| 0x01 | LEGAL_COMPEL | per-commit blocking |
| 0x02 | ART_17_ERASURE | per-commit blocking (encrypted reason) |
| 0x03 | ART_18_RESTRICTION | per-commit blocking (encrypted reason) |
| 0x04 | INTEGRITY_FAIL | per-commit blocking |
| 0x05 | CHAIN_MISMATCH | per-commit blocking |
| 0x06 | PLUGIN_DEPRECATED | class-wide blocking |
| 0x07 | AUTHORITY_DEPRECATED | class-wide blocking |
| 0x08 | DSL_DEPRECATED | class-wide blocking |
| 0x09 | ORACLE_DEPRECATED | class-wide blocking |
| 0x0A | OPT_OUT_ACTIVE | advisory non-blocking |

## Dependencies

- Node.js ≥ 20
- `@noble/curves@^1.x` (Ed25519 verify; already a v3-custody workspace dep)

## Hermeticity verification

```bash
# No network calls
strace -e trace=network -e signal=none node verify-refusal-claim.mjs --help 2>&1 \
  | grep -E "connect|sendto" || echo "no network syscalls"

# No filesystem writes
strace -e trace=write,openat -e signal=none node verify-refusal-claim.mjs --help \
  --pubkey-hex 0x$(printf 'a%.0s' {1..64}) \
  < /dev/null 2>&1 | grep -E "write.*W|openat.*O_WRONLY" || echo "no fs writes"
```

(strace patterns Linux-specific; equivalent on macOS uses `dtruss`.)
