# I built escrow with no escrow agent. Then I tested whether anyone wanted it.

*conditional-sealing was escrow without the escrow agent: data sealed so that no single party — including me — held a working key, released only when a public blockchain confirmed an agreed condition had come true. I built it for three months, March to June 2026. Then I ran a demand test that returned zero clean fits out of 157 candidates, and I retired it. Cryptographically real, operationally unfinished, killed by demand, not by tech. This is the honest version.*

*Built under the working name Cealis; released as conditional-sealing. The repository this essay lives in is its evidence — the construction record is [`paper.md`](paper.md), the design history is [`evolution.md`](evolution.md). Links to the rest are at the end.*

---

## The idea I fell in love with

Every escrow in the world has the same flaw: a middleman who *could* cheat. The lawyer holding the deposit can be bribed. The custodian holding your documents can be hacked, subpoenaed, or simply leak. The trusted third party is the entire mechanism — and also the entire vulnerability. You are not trusting a rule; you are trusting a person to follow a rule.

conditional-sealing was an attempt to remove that person.

The pitch was "escrow with no escrow agent." You hand the system some data. It encrypts that data once, then splits the decryption key into shares and scatters them across several independent parties, so that **no single party — including the operator, which would have been me — ever holds a working key**. Attached to the seal is a machine-checkable condition: a date passes, a loan defaults on-chain, an oracle attests an event, someone stops checking in. A public blockchain, not a human, decides whether that condition is true. The design was: when it fires, the independent parties each sign, the key reassembles itself, and the data is released with a tamper-evident, court-style record of every step. Until then, the data simply has no readable form that anyone can reach. There is no master key to find, because none was ever made.

Under the hood it was, I still think, genuinely elegant. The payload was sealed with ChaCha20-Poly1305. The key was Shamir-split 3-of-3 over GF(2^8) across three signing gates — G2, the Lit Protocol threshold network; G3, the dcipher/drand randomness networks; and G4, a verification component that can only ever *refuse* to sign on narrow legal grounds — all locked behind a fourth gate, G1, a `ConditionEngine` smart contract on a Base testnet that evaluates the condition: the mandatory trigger, holding no share. Miss any one of the four and the threshold fails, so there is no decryption path that bypasses the chain. The key shares were even hybrid post-quantum wrapped (X25519 plus ML-KEM-768), and the whole thing reassembled through a custom `age`-plugin envelope. The load-bearing insight underneath all of it was simple: *on-chain is the one place where a release trigger is objective by construction.* A blockchain can't be talked into lying about whether a condition was met.

I want to be precise about maturity, because the failure was downstream of this. At retirement the cryptographic core was real and tested — byte-exact sealing primitives, golden-vector tested against locked fixtures, the part of the system I trust most. The four-gate combiner was partially built and adversarially tested, though the gate *signing transports* were still stubs: the "independent" parties ran simulated inside one process, on one machine. The `ConditionEngine` plus nine condition modules were deployed on the Base Sepolia testnet. That deployment is testnet-only, has never held real data, and is frozen behind the source: later internal audits found critical issues in the contracts, and two of them were fixed in the code before retirement but never redeployed — so the live testnet contracts still contain them. Treat that deployment as a record that it happened, not as a product. Most of the code was written by AI agents under my direction, in a specification-first pipeline with review gates between phases; I don't write code by hand. The right phrase, the one I made myself say out loud, was **cryptographically real, operationally unfinished**. Non-custody by architecture; the gate signing transports stubbed; operational decentralization never actually realized.

## Why I believed it

The first real use case was lending enforcement. Undercollateralized crypto lenders collect borrower identity for the roughly 2% of loans that default, but they keep that identity sitting in an ordinary database for the 98% that don't. The system would seal that identity as ciphertext nobody could decrypt — until an on-chain default fired — and then release a clean enforcement artifact. The customer was the lending protocol. The pricing had a shape: a retainer, a fee per onboarded borrower, a fee per reveal. The exact numbers I deliberately left open "until two or three partner conversations."

Those conversations never happened. That sentence is the whole post-mortem in miniature, but I'll get there.

I believed it because the architecture was beautiful and the reasoning was clean. I had reasoned the entire thesis from first principles. Every step followed from the last. What I had not done — and this is the part that matters — was check whether the conclusion was *true in the market*, as opposed to merely *valid on paper*. An argument can be airtight and still be about a problem no one will pay to solve.

## The test that killed it

In late May, three months into the build, I finally wrote down a falsifiable filter and called it the Fundability Fingerprint. It is paper-only, costs nothing, and takes an afternoon. A use case is fundable **only if all six conditions hold at once** — a strict AND:

1. The data is *dark* — sealed until trigger, not read live.
2. The trigger is *objective and machine-verifiable*.
3. There is *no standing legal duty* to produce the data early.
4. *Non-custody is the actual requirement*, not a nice-to-have.
5. There is a *paying, motivated check-writer*.
6. There is *no cheap trustless incumbent* already owning the slot.

I want to be exact about what was fixed in advance, because "pre-registered" is a word people inflate. The six conditions and the strict AND were written down before the population run and were not softened afterwards. The size of the population, and what I would do with the answer, were not written down in advance. The instrument was pre-committed; the kill decision was made when the result came in.

I ran it against my own flagship lending thesis on 29 May 2026. The verdict was *confirmed dead*, for two reasons so simple they were almost insulting:

**Recovery fails on insolvency, not on anonymity.** A defaulted borrower who is broke cannot be made to pay by revealing who they are. I had built cryptography to solve identity when the binding constraint was money. **And real institutional borrowers were already KYB'd** — their identity was never the missing input. Every real on-chain default I could find failed on insolvency, not on a missing name. My elegant tripwire was solving a problem the market did not have.

So I did the harder thing and ran the Fingerprint against everything. On 6 June 2026 I put 157 companies and use cases through it, each with a devil's-advocate pass built to kill it. To be exact about what that was: agent-run desk research over public information, directed and adjudicated by me, all in one day — I contacted none of these companies, and the same person who built the instrument judged every verdict. The result: **0 survived clean. Around 26 were wounded. Roughly 131 were dead.** The exact wounded-versus-dead split moves a little between the master summary and the component boards, but the load-bearing number — zero clean fits out of 157 — held identically across every file I checked. The only survivors were narrow, partner-only slivers — bug-bounty proof-of-concepts sealed against payment, clinical-trial interim data, inheritance dead-man's-switches, on-chain property deeds, sports-integrity sealing, music-rights settlement. Every one of them was the *new* deal, the *archival* tier, the *off-mandate* rail. The loud, obvious, data-breach-headline use cases were the *worst* fits of all.

Then I saw why, and it was structural. I call it the scissor.

**Blade A: objective triggers exist, but those customers don't pay.** Machine-verifiable triggers live almost only on-chain — token vesting, DAO key succession, time-locks. Those slots are already owned by trustless incumbents (Safe, Zodiac, Sablier), and the would-be buyers are thin-budget crypto-native teams who build it in-house anyway. Fails conditions 5 and 6.

**Blade B: the payers exist, but their triggers are subjective.** Real enterprises — clinical, finance, defense, health — have budgets. But their release decisions hinge on human judgment: a court ruling, a death certification, a governance vote, a whistleblower triage. There, condition 2 collapses and the system degrades into a glorified audit log. Worse, regulated holders usually have a *standing legal duty to access their own data on demand* — for them, sealing it away isn't a feature, it's non-compliance.

The two blades close on each other. **Objectivity of trigger and ability to pay are negatively correlated across the entire surveyed market.** That is not a gap money fixes or engineering out-builds. It is a property of who has machine-verifiable triggers versus who has budgets. I had built the perfect tool for the empty intersection of a Venn diagram.

I retired the project four days later, on 10 June 2026.

## What I got wrong

Sometimes you're so flashed by what your idea could become that the rest goes invisible. You lose yourself in solving — more features, more edge cases — and the questions you'd ask from the outside stop occurring to you from the inside. That's what happened to me.

The technology was not the mistake. The *sequencing* was.

I spent three months building before I ran a single serious test of demand. The Fingerprint that killed the thesis in one afternoon would have flagged the scissor in week one, for free, before a single line of Solidity. I had the test the whole time — I just ran it after the build instead of before it. A thesis reasoned from first principles but never validated is not a plan; it is a very disciplined guess.

The second thing I got wrong was quieter and more personal: **I was my own outreach bottleneck.** Across the entire life of the project there were *zero* design-partner conversations. Four cold emails went out. Zero replies. I was the sole holder of the message, and I kept rejecting the agent-drafted outreach as not-good-enough while the build ledger filled up with green checkmarks. Build polish is the most comfortable possible way to avoid the terrifying thing, which is asking a stranger whether they actually want what you made. Shipping another subsystem felt like progress. It was displacement activity.

Every unsent email kept the project perfect. The moment a real person on the other end replied "no, we don't need this," the project would stop being a promising system and start being a thing that failed — so I kept finding reasons the draft wasn't ready yet, because rewriting a draft was the one rejection I could control.

The third thing I got wrong was watching the wrong competitor. For months my competitive tracking focused on identity and KYC players, and it correctly found the *language* slot — "conditional sealing," "enforcement" — wide open. But an open vocabulary slot masked a closed *architecture* slot. The real category killer was Zama: confidential compute via fully homomorphic encryption, a roughly $57M Series B in June 2025, mainnet live in December 2025, with lending — the exact slot I was building for — among its named targets. While I was perfecting a bespoke primitive, a far better-funded incumbent shipped the commodity version of the substrate to mainnet during the exact months I was building — and they can compute on the ciphertext, which I could not. I was differentiating on an axis (enforcement versus compliance) that customers were never going to buy on, while the ground moved under the part I thought was my moat.

The fourth thing is the one I was slowest to see, and it is about the design itself, not the market.

From today's view, the interesting thing was never the mechanism. It was the shape we were reaching for: a transparent place to hold ordinary data where no one holds the keys. Not a better custodian — no custodian at all.

We didn't get all the way there. The logic was fine, genuinely — and it was surely better than the normal setup, where one party holds your data and the keys to it and all you get is their promise to behave. But we were still holding the artifacts. The keys were split; the sealed bundles sat with us. The trust problem moved, it didn't disappear. And because I was busy being flashed by the elegant part, I lost scope for the part people would actually question — not whether the math worked, but whether they'd trust us with the pieces we kept.

## What is genuinely worth keeping

Killing a project is not the same as it being worthless. Three things from it are real and portable.

**The cryptographic core.** The sealing primitives, the four-gate combiner design, the hybrid post-quantum key wrapping, the `age`-plugin envelope — that work is sound, tested, and honestly documented, including the corrections found after retirement, which are published rather than patched over. The curated open-source release is this repository — Apache-2.0 for the code, CC BY 4.0 for the specs, with a README that leads with the maturity table and the words *never production, no real data, retired*. If one person learns from the combiner design, the three months bought something.

**The kill-test methodology.** The Fundability Fingerprint and the 157-candidate run are reusable on any future venture. A cheap, falsifiable, six-condition AND test that you are honestly willing to let *kill your idea* is worth more than most pitch decks. I will never again build for three months without one.

**The honesty discipline.** This is the part I'm most proud of, oddly. The whitepaper carried a list of *banned phrasings* — I was not allowed to say "non-custodial" except in the narrow mode where it was fully true, not allowed to say "decentralized," "a subpoena can't open it," or "no one can block it," because the refusal-capable G4 gate made those claims false. When an internal re-audit found critical and high-severity issues in the live contracts, I withdrew my own inflated 5.00/5 maturity grade down to about 3.5/5. That discipline mattered more, not less, because agents wrote most of the code: an agent will happily produce a green checkmark for a claim nobody checked, so every claim had to be traced back to what the code actually did, and then attacked. AI-assisted, human-reviewed, adversarially tested — and still never externally audited, which is why the repository says so on its first screen. Telling the truth about your own work, against your own incentive, is a muscle. This project built mine.

## The lesson

Here is the single corrected instinct, the one sentence I'd tattoo on the next project: **let a falsifiable demand test gate the build, not follow it.**

"Who has both an on-chain trigger and a budget?" should have been question one, not a thing I discovered in month three. The answer — *almost no one* — was the entire business case, available for free, before I wrote any code. Zero design-partner conversations was never a backlog item to get to later. It should have stopped the build in week one. It didn't.

Next time, the order inverts. I find one human who says "I want this" before I make the thing they want. The cheap kill-test comes first; the elegant architecture comes second, if at all.

What's next is already running: I kept the machine that built this — the agent fleet, the specs-first discipline, the kill-tests — and I'm pointing it at the next problems in the reverse order. Demand first, architecture second. The next thing I build will have been asked for before it exists.

conditional-sealing is retired, and I'm at peace with that. The cryptography was real. The discipline was real. The lesson cost me a quarter of full-time work, and I intend to keep it.

---

## Read more

- [`paper.md`](paper.md) — the design and evaluation note: how it was built, what was verified, and the full demand study.
- [`evolution.md`](evolution.md) — three architectures in three months, and the two reversals that mattered.
- [`research/fundability-fingerprint.md`](research/fundability-fingerprint.md) — the six-condition kill test, written up so you can run it on your own idea.
- [`research/kill-test-results.md`](research/kill-test-results.md) — the segment-level data behind 0 of 157.
- [`../README.md`](../README.md) — what is real, what is stubbed, what was never audited.
- [`../ERRATA.md`](../ERRATA.md) — what an agent-run adversarial review pass, directed by me, found wrong after the release was prepared, including one defect in the cryptographic core.
