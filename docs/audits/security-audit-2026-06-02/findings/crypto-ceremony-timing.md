> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Audit reconciliation — crypto/ceremony timing + re-key preimage cluster
HEAD: e87c108 (2026-06-02). Read-only. All evidence grep/read-verified at HEAD.

## TS-CRYPTO-F-05 [HIGH] — re-key h_commit_vN preimage: JSON not SCALE, omits TAG_COMMIT_V3
**Status: PARTIAL** (production-blocked, NOT fixed)

Evidence — `v3-ops/src/ceremony/re-key-stanza-addition.ts`:
- L90-95: `commitAadVn` built as a JS object; `this.commitAadVnCanonical = JSON.stringify(commitAadVn)`.
- L154-162: preimage = `new TextEncoder().encode(this.commitAadVnCanonical)` (JSON string) `‖` `hexToBytes(postReKeyEnvelopeHash)`, then `keccak_256(concat)`. This is exactly the wrong-form preimage the original finding flagged: JSON-of-AAD-as-bytes, NO `TAG_COMMIT_V3` prefix, NOT the 340-byte SCALE/fixed-width 15-field construction per S2-1 §3.4.1.
- L97-153: an explicit inline `SPEC NON-COMPLIANCE — Security-audit-2026-05-14 TS-CRYPTO-F-05` comment documents the gap AND adds a PRODUCTION GUARD: `if (process.env.NODE_ENV === "production")` → throws `CeremonyErrorCode.TRIPWIRE_BYPASS` (L141-153). So in production the wrong value can never be emitted; the legacy JSON path runs only for tests/scaffolding.
- Test `v3-ops/tests/ceremony/re-key-stanza-addition.test.ts` L23, L125 still feeds `JSON.stringify(...)` AAD and asserts deterministic `proposalHash` equality (L80) — i.e. tests still pin the legacy preimage form; the spec-compliant rewrite + test migration (steps 1-3 in the inline comment) have NOT landed.

Verdict: the actual cryptographic defect (non-canonical h_commit_vN) is still present in code; only a runtime tripwire prevents it reaching production. The remediation called for (SCALE byte-exact 340B preimage with TAG_COMMIT_V3, input-shape extension to carry all 15 fields, test fixture migration) is unfinished. PARTIAL, severity stays HIGH.

Fix location: `re-key-stanza-addition.ts` proposal() L90-162 — replace JSON.stringify+TextEncoder with byte-exact 340B preimage using `v3-crypto/src/codecs/commit-context.ts` + `codecs/pda-root.ts`; extend `ReKeyStanzaAdditionInput` to carry the parsed prior CommitAAD (all 15 fixed-width fields); migrate test fixtures at `tests/ceremony/re-key-stanza-addition.test.ts` (~L50/~L80).

## TS-CRYPTO-F-09 [MEDIUM] — gfMul data-dependent timing side-channel
**Status: FIXED**

Evidence — `v3-crypto/src/crypto/shamir.ts` `gfMul` L85-112:
- L90-97: comment explicitly cites `Security-audit-2026-05-14 TS-CRYPTO-F-09`; states the prior `if ((bb & 1) !== 0) product ^= aa` and `if (carry) aa ^= POLY` branches are removed.
- L101: `const bbBitMask = -(bb & 1) & 0xff; product ^= aa & bbBitMask;` — branchless conditional XOR via arithmetic mask.
- L105-106: `const carryMask = -((aa >> 7) & 1) & 0xff; aa = ((aa << 1) & 0xff) ^ (polynomial & carryMask);` — branchless carry reduction.
- Loop is fixed 8 iterations (L99), operation count independent of (a,b) bit pattern.

The exploitable secret-dependent path was `gfMul` (called on share Y-values during Lagrange interpolation at `lagrangeAtZero` L159/L161). `gfPow`/`gfInv` still use square-and-multiply with `if((exp&1))` (L119) but the exponent is the FIXED public constant 254 (`gfInv` L131) — not secret — and operates on x-coordinates (public share indices). So no residual secret-dependent branch. Finding closed.

## F-05 (Phase-1 COSMETIC) — hand-rolled constant-time MAC compare vs crypto.timingSafeEqual
**Status: OPEN (cosmetic preference not adopted) — security property already holds; effectively NOT-APPLICABLE as a defect**

Original recommendation (00-phase1-manual-findings.md L157-171, COSMETIC): swap the manual XOR-diff comparators to `crypto.timingSafeEqual` for clarity-of-intent. It explicitly states "Already secure; this is clarity-of-intent."

At HEAD the 4 originally-cited sites STILL use the hand-rolled XOR-diff-accumulate pattern (`diff |= a[i]^b[i]; return diff===0`, no early exit — mathematically constant-time):
- `v3-crypto/src/envelope/stanza-mac.ts:97-106` (`stanzaMacEquals`)
- `v3-crypto/src/envelope/conditional-recipient-mac.ts:130-135` (`conditionalRecipientMacEquals`)
- `v3-crypto/src/signatures/sigma-subject.ts:140-145` (`bytesEqual`)
- `v3-custody/src/combiner/jcs-canonicalize.ts:54-58 + 66-69` (`bytesEqual` + 32-byte variant)

Seven additional sites share the same correct pattern: `pre-verify-pipeline.ts:333-340` (`bytesEqualIgnoringVersionWindow`, comment-documents constant-time intent), `access-structure/policy-digest.ts:97-102` (`policyDigestEquals`), `g3-dcipher/kem-continuity.ts:69`, `g3-drand/client.ts:323`, `g3-drand/tlock-decap.ts:206`, `g2-lit/dcap-verify.ts:142`, `g4-phase1/refusal-claim-verify.ts:176`.

The ONLY `node:crypto.timingSafeEqual` usage in the packages is `verify-sdk/src/verify-webhook.ts:1,68` (HMAC webhook compare — already native, with explicit length-equality pre-guard). It is NOT one of the F-05 sites.

So the cosmetic swap was NOT adopted; all secret comparisons remain hand-rolled but constant-time. No security defect (XOR-accumulate, no short-circuit). Reporting status OPEN strictly as "recommendation-not-implemented"; underlying severity is COSMETIC and the comparators are secure.

Fix location (optional/cosmetic): the 4 (+7) comparator helpers above — replace with `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` after a length-equality guard.
