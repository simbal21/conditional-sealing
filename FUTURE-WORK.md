# Future work

This repository is archived and not maintained. What follows is not a roadmap — it is the research directions that survived the project's own kill test, recorded so a successor (mine or anyone's) does not have to re-derive them. Everything here may be taken under the published licenses without permission.

## Why this document exists

The Fundability Fingerprint ([`docs/research/`](docs/research/)) returned 0 clean fits out of 157 candidates, and the project was retired on that evidence. But the instrument also produced a ranked map of what *almost* survived, and the build produced components whose value is independent of the demand result. This is the v1 record for whatever comes next.

## The keystone wedge: researcher-side sealed-PoC-against-payment

The closest survivor of the demand study (scored wounded, not clean — see [`docs/research/fundability-fingerprint.md`](docs/research/fundability-fingerprint.md)): a security researcher seals a deterministic, self-verifying exploit that proves a bug is real without revealing the fix path; it releases on a pre-funded, condition-triggered payment. The trigger is objective (the exploit runs or it doesn't) and the distrustful researcher is the motivated payer. The platform-level version fails — bounty validity is a human severity call, and incumbent bounty platforms own the payout slot — so the survivable shape is a thin rail under a researcher's control, not a platform.

What it would take from this repo: the `v3-crypto` envelope essentially as-is; a payment-condition module (`contracts/` ships 9 condition modules as starting points); and a deterministic exploit-verification harness, which is new work and the actual research problem.

## Technical directions independent of demand

- **Independent offline verification.** `verify-sdk` promised release-evidence verification without trusting the operator, and the independence guarantee was never delivered as a shippable SDK. It is arguably the most valuable unbuilt piece: without it, every custody claim bottoms out in "trust the runtime." It is well-specced (`docs/specs/`) and self-contained.
- **Live gate transports.** The AND-combiner is real and adversarially tested; the transports to Lit and drand/dcipher are stubs. Finishing them is engineering, not research — but the operator-disjointness *demonstration* (organizationally, jurisdictionally, TEE-vendor disjoint, actually running on separate infrastructure) has never been done by anyone at this composition, and would be a publishable result on its own.
- **Richer condition attestation at G3.** drand attests only time. dcipher-class networks are the path to arbitrary-event attestation with threshold trust; the G3 interface here was designed for that swap.
- **Constant-time outside a JIT.** The GF(2^8) field arithmetic is constant-time by construction but best-effort under a garbage-collected JavaScript runtime. A port to a language with timing guarantees, plus hardware-level timing evaluation, would upgrade the crypto core's strongest caveat.
- **Witness encryption maturity.** The whole committee apparatus is scaffolding around a primitive that practical witness encryption would subsume. Anyone building in this space should re-check that frontier first.

## Re-running the instrument

The demand study is a single-market, single-period observation with acknowledged solo-rater threats ([`docs/paper.md`](docs/paper.md), section 6). The conditions were pre-committed and the per-segment failure attributions are published precisely so a hostile reader can re-score them. A re-run in changed market conditions — or on a population someone else assembles — is the cheapest way to falsify or extend the load-bearing result. The method (strict-AND, pre-committed conditions, adversarial passes, kill-on-evidence) transfers beyond this category.

## Reuse map

| Take as-is (with review) | Rebuild from spec | Never reuse |
|---|---|---|
| `v3-crypto` primitives + golden fixtures | Gate transports, auth, persistence | The Base Sepolia deployment (predates security fixes; see `deployments/README.md`) |
| Specification corpus (`docs/specs/`, CC BY 4.0) | `verify-sdk` (independence guarantee; spec exists) | Any unqualified custody claim (see the banned-phrasings list in the README) |
| The Fingerprint instrument (`docs/research/`) | Operational runbooks against live networks | |

No support is promised. The [post-mortem essay](docs/postmortem.md) is the right entry point for context; the licenses are the only permission anyone needs.
