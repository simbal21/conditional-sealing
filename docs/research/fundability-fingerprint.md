# The Fundability Fingerprint

### A falsifiable 6-condition test for whether a sealed-data use case can be a real business

*A reusable decision framework for founders evaluating a crypto / privacy-infrastructure idea. Derived from the wind-down of Cealis (a conditional-data-sealing project, built and retired in 2026), sanitized for public release. No private companies or individuals are named; everything below is methodology, aggregate counts, and category-level patterns.*

---

## 0. Why this exists

Most privacy and crypto infrastructure dies on demand, not on technology. The cryptography works; nobody is willing to pay for it. The trouble is that "is the cryptography real?" is a question a founder can answer alone, in the build, and feel good about — while "will anyone buy this?" is a question that requires other people and is therefore easy to defer.

The Fundability Fingerprint is the cheap, paper-only, falsifiable filter that lets you answer the second question *before* you write the code instead of after. It was originally built to test one specific architecture — **conditional sealing** ("escrow with no escrow agent": data sealed so that no single party can open it early, fake the trigger, or leak it, releasing only when a machine-verifiable condition fires). But the test generalizes to any infrastructure whose pitch is *"we make a sensitive thing release/compute/unlock only when a condition is met, and you don't have to trust a custodian."*

The honest origin matters, so state it plainly: the project that produced this test ran about three months of building before it ran the test seriously. The test took an afternoon and killed the thesis. That asymmetry is the entire lesson. **Run this before the build, not after it.**

A note on what this test is and is not. It does not tell you whether your idea is *clever*, *novel*, or *technically sound* — it assumes all three and asks a colder question: is there a buyer whose problem actually has the shape your tool requires? A use case can be brilliant engineering and still fail every condition below.

---

## 1. The six conditions

A sealed-data / conditional-release use case is **fundable only if all six of the following hold.** Each is phrased so it can be answered honestly by a hostile reader. Each comes with *why it matters* and *the failure mode it catches*.

### Condition 1 — Dark data

**The data is sealed until a trigger; it is not read live.**

The whole value of conditional sealing is that the payload sits unreadable until a condition fires. If the customer needs to read, query, or compute on the data continuously — the normal state of operational data — then "seal it until later" is structurally impossible.

*Why it matters:* This is the difference between your category (conditional release) and the much larger, already-owned category (encryption-at-rest, DLP, zero-trust access control). If the data must be live, the standard security stack already serves the customer better than you can.

*Failure mode it catches:* The most viscerally alarming "data breach" stories are usually live-read systems — active databases, operational records, files under continuous engineering or analysis. Sealing them is not an option for the holder, so the breach headline is a trap, not a lead.

### Condition 2 — Objective, machine-verifiable trigger

**The release event is a fact a machine can check without human judgment.**

A date passing, a block height reached, an on-chain default, a payment confirmed, a signature collected, a liveness check lapsing — these are objective. A court ruling, a death certification, a "best-efforts" earnout, a whistleblower-triage decision, a governance vote, a "misuse" finding, a milestone someone has to *certify* — these are subjective.

*Why it matters:* Conditional sealing's only honest "why blockchain" is that **on-chain is one of the few places a release trigger is objective by construction.** Remove the objective trigger and the system collapses to a glorified audit log: it can seal the data, but it cannot make a human decision trustworthy.

*Failure mode it catches:* Founders smuggle subjectivity in through an oracle ("an oracle attests the event") without noticing the oracle is just relaying a human judgment. If a person decides whether the condition is met, Condition 2 fails no matter how the decision is transported.

### Condition 3 — No standing legal duty to produce the data early

**The holder is not legally obligated to hand the data over on demand.**

If a regulator, court, or counterparty can compel production at any time, then making yourself *unable* to produce the data is not a feature — it is non-compliance, or a crime.

*Why it matters:* This condition quietly disqualifies most regulated holders, who are precisely the parties with budgets. KYC/AML retention, clinical-lab data, defense technical data, tax-reporting platforms — all carry an affirmative duty to produce. A tool whose selling point is "even we can't get it" is, for them, a liability generator.

*Failure mode it catches:* The "we make your data untouchable" pitch lands hardest exactly where it is most dangerous to the buyer. The buyer's compliance officer kills the deal in one sentence.

### Condition 4 — Non-custody is the actual requirement

**"No single party can open it" must be a hard requirement of the deal, not a nice-to-have.**

There must be a real-world reason the parties cannot simply trust a custodian: the custodian is the adversary, or the parties don't trust each other, or a regulator demands provable non-access. If a trusted escrow agent, a multisig, or "we promise we won't look" would satisfy the customer, the expensive no-master-key architecture is over-engineering.

*Why it matters:* Non-custody is costly — operationally, legally, and in user experience. If the customer would accept custody, they will accept the cheaper custodial product, and they will choose it.

*Failure mode it catches:* The founder's conviction that non-custody is obviously better than custody. It usually isn't, to the buyer. Demand a concrete actor whose ability to peek is the deal-breaker; if you can't name them, this condition fails.

### Condition 5 — A paying, motivated check-writer

**There is a specific party who both needs the constraint and has a budget to pay for it.**

Not "the ecosystem benefits." A named role with money who is *motivated* to buy.

*Why it matters:* The party who needs the constraint is frequently the party who least wants it. Cleanup crews, custodians whose product *is* being the trusted reader, and bad actors all profit from the data staying exactly as it is. Meanwhile the parties who would benefit from sealing are often broke: defunct entities, grant-gated non-profits, or thin-budget crypto-native teams who will just build it themselves.

*Failure mode it catches:* "Who pays?" answered with a beneficiary instead of a buyer. If the only motivated party can't write a check, or the only party who can write a check isn't motivated, Condition 5 fails.

### Condition 6 — No trustless / cheap incumbent already owning the slot

**There is no existing trustless or near-free solution the customer already uses for the easy version of the problem.**

If a multisig + delay module + recovery flow, an on-chain vesting/streaming protocol, a confidential-compute platform, a software-escrow incumbent, or a ~$0 timestamping standard already covers the customer's case, you are not selling a new capability — you are asking them to switch off something that already works and costs nothing.

*Why it matters:* Trustless incumbents don't behave like normal competitors. They are open-source, composable, and often free, so there is no price umbrella to undercut and no trust gap to exploit. They simply absorb the slot.

*Failure mode it catches:* The founder who tracks the *vocabulary* competitor (people using similar language) while missing the *substrate* competitor (people shipping the commodity primitive). The dangerous incumbent is usually the one solving the problem more generally and more cheaply, not the one using your words.

---

## 2. Why it's a strict AND — the kill-test logic

The Fingerprint is deliberately a **strict AND of all six conditions**, not a weighted score. A use case that satisfies five conditions and fails one is not "83% fundable" — it is dead, because the single failed condition is sufficient to remove the buyer.

This is the design choice that turns a checklist into a kill test:

- **Each condition is individually necessary.** A subjective trigger (C2) is fatal even if everything else is perfect, because the product becomes an audit log. A standing legal duty (C3) is fatal even with a perfect trigger, because the buyer can't legally adopt it. A trustless incumbent (C6) is fatal even with a desperate, well-funded buyer, because the buyer already has a free answer.
- **Weighted scoring hides the kill.** Average six conditions and a fatal failure gets diluted by five passes into a comfortable-looking number. The AND refuses that comfort. It forces you to say *which* condition fails and accept that one failure ends the conversation.
- **The output is a verdict, not a ranking.** The test does not produce "good / better / best." It produces **survives / dies**, plus — for the near-misses — an explicit note of *which* condition is shaky and whether a narrower slice of the same customer could pass cleanly.

The strict AND is also what makes the test *cheap*. You don't have to model market size, pricing, or go-to-market. You ask six binary questions, and the first hard "no" ends the evaluation. Most candidates die on the first or second question, in minutes.

---

## 3. The kill-test methodology

The Fingerprint is the filter; the kill test is the procedure for running it across a population of candidate use cases. The discipline is what makes the result trustworthy.

**1. Build a candidate population, not a shortlist.** Hunt broadly — across known fields where you already suspect fit *and* across fresh field clusters you've never examined. Breadth is the point: a filter you only run on your favorite ideas tells you nothing. Deliberately include the "obvious wins" you are emotionally attached to.

**2. Assign each candidate to an adversary.** Each use case is evaluated by an independent **devil's-advocate pass** whose job is to *kill* it, not to find a way to make it work. The default posture is rejection; the candidate must earn survival against all six conditions. This inversion is essential — a founder evaluating their own ideas will reach for the one slice that passes and call the whole use case fundable.

**3. Apply the strict AND, condition by condition.** For each candidate, walk the six conditions and record the first hard failure. Name the failing condition explicitly. Do not stop at "feels weak"; state which machine-checkable condition is violated and why.

**4. Sort into a three-bucket verdict taxonomy:**
   - **Survived** — clears all six conditions cleanly. A real, head-on business.
   - **Wounded** — one or two conditions are shaky, but a *narrow, honest, forward-only* slice of the customer's problem survives. Not a product; a partner-fit conversation worth having.
   - **Dead** — at least one hard failure with no honest fit.

**5. Read the death distribution, not just the verdicts.** The value isn't only "how many survived" — it's *which conditions did the killing, and how often.* The failure pattern is the map of where your category structurally does and does not fit. Clustered failures reveal a market property, not bad luck.

**6. Keep the honesty discipline.** Use the same banned-phrasings rule the rest of the project used: no "a subpoena can't open it," no "no one can block it," no unqualified "non-custodial" or "decentralized" claims the architecture can't back. A test that lets you lie to yourself about the product will let you lie to yourself about the market.

A worked single-case example came first. Before the population run, the Fingerprint was applied to the project's own flagship thesis — sealing borrower identity for undercollateralized on-chain lending and releasing it on default. It failed on a near-napkin argument: **recovery fails on insolvency, not on anonymity** (a broke defaulter cannot be made to pay by revealing who they are), and the real institutional borrowers were **already identity-verified**, so identity was never the missing input. Condition 4 collapsed (non-custody of identity was not the binding requirement) and Condition 5 with it (no motivated payer for a non-solution). That single clean kill is what justified running the full population test.

---

## 4. Aggregate result of the population run

The test was run across a population of **157 candidate use cases**, each devil's-advocate tested against the full six-condition Fingerprint, spanning known fields plus a set of never-before-examined field clusters.

### Headline

| Verdict | Count |
| --- | --- |
| **Survived (clears all 6 cleanly)** | **0** |
| Wounded (narrow honest slice survives) | ~26 |
| Dead (≥1 hard failure) | ~131 |
| **Total tested** | **157** |

**The load-bearing finding is the zero.** Across 157 candidates, *not one* cleared all six conditions head-on. This number is identical across every file that recorded the run; it is the most robust output of the entire exercise.

*Honesty note on the split.* The wounded/dead division is softer than the zero. The top-level summary records ~26 wounded / ~131 dead; the underlying component boards sum to 18 wounded / 139 dead (the difference is borderline candidates folded into "wounded" at the summary level). The disagreement is purely about where to draw the wounded/dead line on marginal cases — it does not touch the load-bearing result, which is **zero clean survivors** in all accounts.

The full aggregate behind this headline — every segment tested, verdict counts per segment, and which conditions did the killing in each — is published in [kill-test-results.md](./kill-test-results.md).

### Failure-pattern distribution (which conditions did the killing)

The 131 deaths were not random; they clustered on a small number of conditions. In order of how often each was the killer:

1. **Condition 2 — no objective trigger. The #1 killer by a wide margin.** Whenever the release event was a human, legal, or governance *judgment* (a ruling, a certification, a vote, a triage decision, a subjective milestone or earnout), the system collapsed to an audit log. This was the single most common cause of death and the most important strategic boundary: *if the trigger isn't machine-verifiable, walk away.*
2. **Condition 1 — data isn't dark.** A large swath of candidates were live-read / live-compute problems (operational records under continuous use). Sealing-until-trigger is structurally impossible for them; they belong to the encryption-at-rest / DLP / zero-trust stack that already owns them.
3. **Condition 6 — a trustless / cheap incumbent already owns the easy version.** The same incumbents recurred: multisig + delay-module + recovery stacks and on-chain vesting/streaming protocols owning every on-chain custody / key-succession / vesting case; confidential-compute platforms owning the no-single-party conditional-decrypt slot; software-escrow incumbents owning code escrow; and a ~$0 timestamping standard killing every "prove I submitted on date X" wedge.
4. **Condition 5 — no paying, motivated check-writer.** Many of the loudest pains belonged to defunct/bankrupt entities, broke or grant-gated non-profits, or parties who actively *profit from the data staying buried.* The party who needs the constraint was often the party who least wants it.
5. **Condition 3 — a standing duty to produce.** Regulated holders (KYC/AML, clinical, defense technical data, tax-reporting) are legally obligated to produce on demand; self-disablement is non-compliance, not a feature.

**Condition 4 (non-custody is the actual requirement) rarely appeared as the *recorded* killer in the population run** — not because it is easy to pass, but because candidates usually died earlier in the AND chain (on C2 or C1) before C4 was reached. In the single-case flagship kill, by contrast, C4 was the decisive failure. The ordering in which conditions kill is itself information: the earlier conditions are doing most of the screening.

---

## 5. The scissor — the structural result

The death distribution wasn't just a list of failures; it revealed a *market structure.* Across the surveyed population, **objectivity of the trigger and ability-to-pay are negatively correlated.** This is the central transferable finding, and it is a scissor with two blades:

**Blade A — objective triggers exist, but the customers don't pay.** Machine-verifiable triggers live almost exclusively on-chain (vesting, key-succession, time-locks, payment events). Those slots are already owned by trustless incumbents, and the would-be buyers are thin-budget crypto-native teams who build in-house. → fails **C5 (no payer)** and **C6 (incumbent)**.

**Blade B — the payers exist, but their triggers are subjective.** Real enterprises (clinical, KYC, defense, health, finance) have budgets, but their release decisions hinge on human/legal/governance judgment. → fails **C2 (no objective trigger)**, and frequently also **C1 (data is live-read)** and **C3 (standing duty to produce)** on top.

**The two blades close on each other.** Where the trigger is clean, the money isn't; where the money is, the trigger isn't. This is not a gap that funding or engineering closes — it is a structural property of *who has machine-verifiable triggers versus who has budgets.* You cannot out-build a negative correlation in the market itself.

For a founder, the scissor compresses into a single first-question: **"Who has both an on-chain (objective) trigger and a budget?"** If the honest answer is "almost no one," that answer *is* your business case, and you have it before writing a line of code.

A category-killer made the scissor sharper still. During the same months, a well-funded confidential-compute incumbent (FHE-based, ~$57M Series B in mid-2025, mainnet late 2025) shipped a commodity primitive doing no-single-party conditional decryption *and* computing on ciphertext, explicitly targeting the same uncollateralized-lending use case — the exact Blade-A slot. This is the C6 lesson in the flesh: the dangerous competitor was the one shipping the general, cheap *substrate*, not the one using similar vocabulary.

---

## 6. The surviving shapes (category level)

Zero candidates survived *head-on.* But the ~26 wounded entries shared a recognizable geometry, and that geometry is the most useful output for any founder in this space. **Every survivor was the new deal, the archival tier, or the off-mandate rail — quiet, narrow, forward-looking, and partner-fit rather than a head-on product sale.** The most spectacular breach headlines were consistently the *worst* fits; the fundable slivers were unglamorous.

The surviving shapes, described as categories (no companies named):

- **Bug-bounty sealed proof-of-concept against payment (the keystone shape).** A researcher seals a deterministic, self-verifying exploit that proves the bug is real *without revealing the fix path*; it releases on a pre-funded, condition-triggered payment. This turns the subjective "is the bug valid?" fight into an objective, machine-checkable release. This is the wedge that comes *closest* to clearing all six conditions — which is why it is the keystone — but it was still scored **wounded, not a clean head-on survivor.** The strong part is the narrow *researcher-side* slice: for a deterministic exploit that either runs or it doesn't, the trigger is objective (C2) and the distrustful researcher is the motivated payer (C5). The broader *platform-level* version is what fails — bounty validity is in practice a human-judged severity call, not a pure pass/fail (C2 fails), and existing bounty platforms already run multisig-vault payouts plus on-chain arbitration stacks that own much of the slot (C6 fails). So the survivable shape is the thin sealed-PoC-against-payment rail *under a researcher's control*, not a new bounty platform — consistent with the load-bearing result that zero candidates cleared all six head-on.

- **Clinical-trial interim-data sealing (pre-database-lock).** A sponsor, a contract research org, and an independent monitoring committee each hold unblinded interim data nobody should read before lock. Seal the interim package so not even the holder's own admins can read it until the *calendar/database-lock* event (objective) auto-releases it. The buyer is the *sponsor* mandating sealed interim storage as a contract term — not the data-handler.

- **Inheritance / dead-man's-switch (liveness-lapse variant only).** A non-custodial payload that unlocks on an on-chain timelock or liveness-lapse trigger no single party can fire early or suppress. Survives only in the *objective-trigger* variant; the death-certification variant dies on C2 (death is an off-chain human attestation). The honest shape is a payload/release layer *under* an existing front-end, not a competing consumer app.

- **On-chain-deed property closing escrow (deed-recorded variant only).** Condition-gated release of closing funds that fires on the machine-verifiable *deed-recorded* event, so even the platform can't move funds before close. Survives only here; the construction-milestone variant dies on C2 (no objective oracle for "construction complete").

- **Sports-integrity pre-event sealing (pre-commitment variant only).** Seal a decision (lineup, injury status, trade) at the instant it's made and prove it was unopened until an official *embargo-lift* trigger. Survives as pre-commitment with an objective embargo trigger; the conditional-reveal-on-investigation variant dies on C2 (an investigation opening is a human judgment).

- **Music-rights split-settlement (off-mandate, pre-signed-split variant only).** For works where co-owners have *already signed* their split (objective, on-chain), a non-custodial settlement rail that releases when every co-owner's signature is present. Survives only off the statutory mandate and only where the split is already objective; the attribution-dispute variant dies on C2.

**The common thread is the transferable part.** Every survivor (a) has an objective trigger that already exists in the customer's world (a date, a signature set, a recorded event, a deterministic test) rather than one you have to manufacture; (b) is sold as a *value-creation* story — a new deal or relationship that couldn't happen today becomes possible — not a *recovery* story; (c) is approached as a partner-fit / composable layer beneath an existing product, not a head-on displacement; and (d) sits on the forward-looking or archival edge of the problem, never the live operational core. If a sealed-data idea does not have all four of those properties, the population evidence says it will not survive the Fingerprint either.

---

## 7. How to use this as a founder

The framework is the IP. To apply it to your own crypto / privacy-infra idea:

1. **Run the Fingerprint before you build, not after.** It is paper-only and costs an afternoon. A thesis "reasoned from first principles but never validated" is still an untested hypothesis, however elegant. The cheapest possible moment to learn your use case fails C2 is week one.

2. **Make the first question "who has both an objective trigger and a budget?"** That single question front-loads the scissor. If you can't name a role that has both, you have found the structural problem before spending anything.

3. **Assign an adversary, not an advocate.** Evaluate each use case with someone (or some process) whose explicit job is to kill it on the six conditions. Your own enthusiasm will always find the one slice that passes and over-generalize it.

4. **Read the death distribution as a market map.** When many candidates die on the same condition, that is not bad luck — it is telling you a structural feature of who has triggers versus who has money. Treat clustered failures as a finding.

5. **Watch the substrate competitor, not the vocabulary competitor (C6).** The incumbent that kills you is usually the one shipping the cheaper, more general primitive — not the one using your marketing words. Track the commodity substrate's roadmap as if it were your own.

6. **Treat zero design-partner conversations as a five-alarm signal.** Months of building with no customer who has said "I want this" is not a backlog item; it is the product risk made visible. Build polish in that state is displacement activity. One human saying "I want this" is worth more than the next thousand commits.

7. **Let the falsifiable demand test gate the build — don't let the build outrun it.** The corrected instinct, stated once: put the cheap kill-test *first*, and let it decide whether the expensive work begins.

---

## 8. Provenance, honesty, and limits

- **Origin.** This framework was developed and applied during the wind-down of Cealis, a conditional-data-sealing project (workspace name confirmed as *Cealis*; public release name undecided). Cealis was, in its own honest verdict, "cryptographically real, operationally unfinished." Its custody design was *non-custody by architecture* (a multi-gate AND combiner with no master key), but at retirement the gate signing transports were stubbed and operational decentralization was not realized — so the architecture's strongest claims were not all live. The project itself maintained a banned-phrasings list ("a subpoena can't open it," "no one can block it," unqualified "non-custodial" / "decentralized") precisely because the design was refusal-capable and legal-compel-aware. That self-discipline is part of why the kill-test was trustworthy: a team honest about its own claims is more likely to be honest about its market.

- **Why Cealis was retired.** Not the technology — the demand-side scissor of §5. The Fingerprint killed the flagship thesis (2026-05-29), the 157-candidate population run confirmed it across the market (2026-06-06), and the project was retired (2026-06-10). At retirement it had 0 paying customers and 0 design-partner conversations.

- **What is solid vs. soft in the numbers.** Solid: **157 tested, 0 clean survivors**, the ranked failure distribution, and the scissor — these are consistent across all source files. Soft: the exact wounded/dead split (~26/~131 at summary level vs. 18/139 in the component boards), a classification difference on borderline cases that does not affect the load-bearing zero.

- **Scope limits of the test.** The Fingerprint screens *demand shape*, not technical feasibility, market size, pricing, or timing. It will tell you whether a buyer with the right-shaped problem exists; it will not size that buyer or tell you how to reach them. It is also specific to the conditional-release / sealed-data category — the six conditions are tuned to that architecture, though the *method* (a strict-AND falsifiable filter, run adversarially across a broad population, read by its death distribution) transfers to any infrastructure thesis.

- **The one-line takeaway.** A falsifiable, six-condition, strict-AND demand test, run adversarially across a broad candidate population *before* building, would have surfaced the structural scissor in week one. The transferable IP is not the six conditions alone — it is the discipline of letting a cheap kill-test gate the expensive build.
