# Where can a restarted enclave get the truth about "now"? — a study for the auditor

**Date:** 2026-11-05 · **Status:** a study, not a REQ — the owner asked the auditor to think along.
**Decision (owner, 2026-11-05):** the current hardware stays on R7; the roadmap is a physical TPM on the
operator's own FLC server, or Trusted Launch on Azure for a vTPM counter (§3.5). The control coin
(§3) is **not pursued — too complex**; it is kept here only as the record of what else exists.
**Question:** after a restart, an enclave cannot tell the latest copy of its own sealed state from
an older one. R7 answers with the owner's signature per start. We believe no other source of
freshness exists *on the server*; this document states that argument so it can be attacked, and
develops the one alternative that does not need a human — **Bitcoin itself as the record of
truth** — far enough to be judged.

**Кратко по-русски.** Запечатанное состояние доказывает авторство, не свежесть; память умирает с
процессом, диск откатывается. Поэтому любой автоматический критерий «можно продолжать» на самом
сервере — задержка, малый бюджет, «файлы на месте» — обходится откатом. Источники свежести только
снаружи: подпись владельца (R7), сама цепочка Биткойна (контрольная монета), внешний счётчик
(TPM/свидетель). Ниже — почему, и как цепочка может стать таким счётчиком.

## 1. The fact

Two stores exist for an enclave: its process memory, which dies with the process, and the disk,
which root controls. The sealed blob on disk is encrypted and MAC'd with a key only this enclave
code on this CPU can derive, so root cannot read or alter it — but root can keep every copy the
enclave ever wrote and present any of them at the next load. The MAC proves *who wrote it*, never
*which one is the latest*. SGX offers no persistent monotonic counter (the Platform Service
Enclave counters are gone) and no trusted clock. A rollback is therefore always possible and
always invisible from the inside, and it is repeatable: every cycle re-pays the window's budget
(`THREAT-MODEL.md §5`, confirmed 2026-11-05).

## 2. Why nothing on the server can fix it

Any rule of the form "after a restart, continue automatically when X" fails if X is computed from
what the server holds:

| X | Why it fails |
|---|---|
| "the files are in place" | an older copy is in place too; indistinguishable |
| "a small budget until the owner looks" | root restarts a thousand times; the restart count has nowhere to live (memory dies, disk rolls back) |
| "N blocks of headers since the restart" | root restores a week-old state and feeds the real headers of that week — already mined, available in seconds; the delay is measured from a past the attacker knows in advance |
| "the clock says enough time passed" | the enclave has no clock; the header feed is root's |
| "the receipt log / a signed journal is intact" | root restores the journal together with the state; a signature proves authorship, not recency |

Freshness has to come from something root cannot roll back. Three such things exist:

1. **The owner** (R7): a signature over a challenge drawn at this load. Costs a human step per
   restart; nothing else.
2. **The Bitcoin chain**: the one external, append-only, root-proof record the enclave already
   verifies (headers) and already writes to (its own transactions).
3. **A live hardware counter the host cannot decrement**: a TPM NV counter read through a
   TPM-signed certify with an enclave nonce. On a cloud VM the vTPM belongs to the hypervisor — it
   defends against root *inside* the VM, not against the provider, who is the adversary of
   scenario 3. (A *witness* that signs over the enclave's nonce — the freshness witness, developer
   tooling — is **source 1** in another coat: an external party that must be reachable at each
   restart, with the same liveness cost as the owner; the auditor's regrouping, §5.)

We do not see a fourth. The auditor's answer (§5): there are exactly three, and here is why.

## 3. Bitcoin as the record of truth — the control coin, developed

### 3.1 The idea

Make every transaction the enclave signs **spend a designated control coin and recreate it**, so
the wallet's outgoing history is one linear chain of its own transactions. The sealed state
remembers the current control outpoint. A rolled-back state remembers an *older* control coin,
which the chain has already spent: everything a rolled-back enclave signs is a double-spend and
cannot be mined. The budget counter in sealed state is thereby **anchored to the chain**: root can
only extend the mined lineage, which is exactly what honest operation does. No human, no monitor,
no witness; the enclave needs nothing it does not already have (full previous transactions come
with every PSBT; headers it verifies).

### 3.2 Rules

- **Birth.** The control coin is created by the first enclave-signed transaction after `init` —
  the mandate-install transaction — from the owner's first funding: a small output at a dedicated
  derivation (branch 2, index 0) plus an `OP_RETURN` committing to the installed mandate's hash.
  Until that transaction is **`maxReorg` deep** (an SPV proof against the enclave's own header
  chain — a Merkle branch, ~1 KB — plus `maxReorg` headers on top), the enclave treats no control
  coin as live: the birth is the one-time, attended genesis the whole scheme rests on, so it pays
  full finality; later links may chain shallower for throughput (auditor, §5).
- **Every signing.** A PSBT is judged only if one input is the current control coin and exactly
  one output recreates it at the next index; the enclave accepts as the next link any confirmed or
  unconfirmed transaction that spends the current coin and recreates the script (so RBF
  replacements do not strand the lineage — the full previous transaction is verified anyway).
- **Budget accounting** is charged against the lineage link that was mined, not per signed
  candidate (auditor's point (3)): two candidates for one link conflict on chain; one is charged
  when its successor's previous transaction names it.
- **Policy transitions** split by direction, the asymmetry the mandate already has. A
  **tightening** (cancel, freeze, a lower cap, a rotation to a safer key) applies **at once** —
  delaying protection to wait for a block is the wrong direction, and a rollback of a tightening
  only returns to the looser prior state, which the anchor already covers. A **loosening** (a
  higher cap, unfreeze, rotate-owner) spends the control coin in a tiny transaction carrying the
  message hash in `OP_RETURN`, and its activation height is `max(timelock height, the height at
  which that spend is SPV-proved)`: the chain proof is the anchored twin of the timelock. The
  owner, present for owner operations anyway, waits for that confirmation (auditor, §5).
- **Several lineages.** Throughput can be multiplied safely by `m` **fixed** lineages with the
  window budget **partitioned** across them (shares summing to the total); the anti-rollback
  property holds per lineage, the sum stays the bound; `m` changes only by an attended policy
  operation; the price is `m` control coins to manage (auditor, §5). A shared pool is probably
  safe too (the coins are the anchor, not the counter) but needs its own proof; partitioned is
  safe by construction.
- **Finality.** The scheme's safety equals Bitcoin's finality assumption: two *mined* branches of
  one lineage need a reorg deeper than `maxReorg`, the boundary the mandate already names; set
  the lineage's finality to `maxReorg` and the question answers itself (auditor, §5).
- **Windows** stay in block heights; headers can only *delay* a window (withholding), never add
  budget (auditor's point (2)); the control coin is the backstop even if the window counter is
  gamed by re-fed headers.
- **Re-anchor** (liveness): a dropped or reorged lineage is repaired by an owner-signed, nonce'd
  message naming a new control outpoint with its SPV proof; replaying an old re-anchor after a
  rollback names an already-spent coin.
- **Completeness** (auditor's gating condition): *every* ecall that can sign — payout, fee-bump,
  consolidation, sweep, recovery spend — goes through the same JUDGE+SIGN pair, which enforces
  the control-coin rule in `signer-core`, not in the plugin; one exempt path voids the scheme.

### 3.3 What it buys and what it costs

| | R7 (owner arms each start) | Control coin |
|---|---|---|
| unattended restart | pause until the owner signs | continues |
| rollback by root | silent enclave until the owner; residual = one window per start the owner approves without looking | signatures are double-spends; residual = none from rollback (the mandate's rate is the bound) |
| human in the loop | one signature per restart | none for restarts; owner waits one block per policy change |
| per-payout cost | — | +1 input, +1 output (a few hundred sat), payouts **serialized** on one lineage (mempool ancestor limits ≈ 25 unconfirmed per block) |
| enclave code | one message, one volatile flag | the lineage rule in judge, SPV (Merkle) verification, the re-anchor message, OP_RETURN handling, confirmed-birth rule |
| plugin | — | PSBTs must include the control coin (enclave-enforced; a lying plugin only gets refusals) |
| audit | done (SOURCE IMPL-PASS) | a DESIGN REQ; the auditor's first look (2026-11-05): sound, with (1)–(4) + completeness + serialization as the owner's cost to weigh |

### 3.4 Could the two combine?

Yes, cleanly: the control coin is the default rule, and R7's arm is kept as the owner's
emergency stop (an unarmed enclave is still a useful state) — but that is two mechanisms, and the
owner's rule is to prefer one. The honest framing: **R7 for the merchant whose server reboots when
they are awake; the control coin for the operator who cannot have a pause.** Both are stated; one
is built.

The auditor's synthesis (§5) puts the three options on one line, and it is the story to tell:

| | attended? | the loss bound against root | cost |
|---|---|---|---|
| **R7** (owner arms each start) | yes, one signature per restart | kept | none |
| **control coin** | no | kept — **moved onto the chain** | SPV in the TCB, serialized (or partitioned) payouts, a confirmation per loosening |
| **`AUTO_ARM`** | no | **forfeited** (the hot-wallet float) | near zero |

So for "the operator who cannot have a pause" the control coin is strictly better than
`AUTO_ARM`: the same unattendedness with the bound intact. `AUTO_ARM` remains what it is — the
labeled opt-out — and the control coin is the principled answer to the question it tries to
answer.

## 3.5 Source 3 on Azure, once the provider is trusted (owner's decision, 2026-11-05)

The owner accepts the cloud provider as a residual — the posture of every provider-hosted TEE
(AWS Nitro rests on it entirely). Then the adversary of scenario 3 is root *inside* the VM, and
the hypervisor-owned **vTPM** becomes a legitimate live hardware counter: unattended restarts with
the bound kept, without SPV in the TCB and without serialized payouts.

Sketch: at `init` (attended) the owner verifies the vTPM's endorsement chain **on the laptop**
(Microsoft's CA; X.509 stays out of the enclave) and hands the enclave the public key of an
**ECC P-256 attestation key** created in that vTPM, which is sealed next to the owner key; an NV
monotonic counter is allocated for the wallet. On every seal the host increments the counter and
the enclave records the expected value in the state; on every load — and on every ecall that
reads a blob — the host must present `TPM2_NV_Certify` over the counter with the **enclave's
fresh nonce** as qualifying data, signed by that AK; the enclave verifies the P-256 signature
(code it already has) and that `counter == state.counter`. A rolled-back blob expects a smaller
value than the counter shows: refused, and the owner's `Arm` (R7) remains the attended override
for that and for the crash-between-increment-and-write case. Root can increment the counter
(DoS at most), cannot decrement it, cannot forge the AK's signature, cannot replay a certify
(nonce), cannot swap in a software TPM (different AK). TCB addition: parsing one fixed TPM2
attestation structure; no new crate beyond what P-256 verification already needs.

Facts to settle before a REQ: the project's node `sgx-node-3` exposes **no** `/dev/tpm0` today
(it was not created with Trusted Launch); whether DCsv3 can be created with a vTPM is to be
verified on Azure's side; the NV index is shared TPM state and must be allocated under the same
co-tenancy rules as every other resource. On the owner's own FLC bare metal the physical TPM is
the same design with no provider in the picture.

## 4. Questions for the auditor

1. §2: is the list of freshness sources complete? Any fourth source we are missing?
2. §3.2 "accepts as the next link any transaction that spends the current coin and recreates the
   script": can root fork the lineage into two *mined* branches? (We think not: two spends of one
   coin conflict.)
3. §3.2 policy transitions through the control coin: is "apply after SPV proof" the right rule,
   or is "apply at once, the chain only protects against rollback" acceptable with a labeled
   residual (root withholds the broadcast → the owner sees no confirmation → knows)?
4. The confirmed-birth rule: is one confirmation enough, or `maxReorg`?
5. Anything in the serialization cost that could be relaxed safely (e.g. several control coins =
   several lineages, each with a share of the budget)?

Nothing here changes the shipped code; this is the map of what else exists, for the record and for
the day an operator needs unattended restarts.

## 5. The auditor's answer (2026-11-05, recorded verbatim)

Read the study. §2 is correct and the three sources are complete — and I can give you the reason it's complete, not just "I don't see a fourth."

WHY EXACTLY THREE. Rollback-freshness is two sub-problems: P1 — the reference must sit where root can't rewind it (off the server); P2 — the enclave must tell a current reference-value from an old one root replays. P1 forces an EXTERNAL root of trust. P2 has exactly three solution-shapes, and each is one of your sources:
- interactive: the enclave emits a fresh nonce, an external PARTY signs over it → the answer provably post-dates the nonce. = source 1 (owner). Cost is intrinsic: the party must be online at restart (the pause).
- self-evidencing via consensus work: the reference carries PoW the enclave can verify, so a stale value is intrinsically unusable — your control-coin trick: a rolled-back coin is provably spent in a work-backed block, so the CHAIN rejects stale state and the enclave need not detect it. = source 2. Cost: SPV in the TCB + serialization.
- live hardware read: the enclave reads a physically-monotonic counter NOW. = source 3. Cost: trust in the hardware, i.e. the cloud provider's vTPM.
A fourth source would need a fourth way to solve P2, and there isn't one: you either have someone fresh vouch (party), have the staleness be self-rejecting through work (consensus), or read a live tamper-proof device (hardware). Everything I could invent collapses into these — a roughtime/TSA signature or a drand/NIST beacon is source 1 (an external signer over your nonce; replay-prone exactly like the witness unless it signs your challenge); a remote attesting enclave is source 1 too, and a THRESHOLD of them is just source 1 distributed — which is, notably, the TRUST stack's own FROST model, the one escape from "one owner must be awake" that stays in the signature family. A VDF or an accumulator anchors nothing external (root rolls back the seed/the updater). So: no fourth. One regrouping for §2 item 3 — separate a witness that SIGNS over your nonce (that's source 1, with the owner's liveness cost) from a hardware COUNTER (source 3); the doc blurs them, and the difference is whether a human/box must be reachable at each restart.

The five:

(2) Fork into two MINED branches — no. Two spends of one coin conflict; a single chain mines one. The only way to two final branches is a reorg deeper than maxReorg, which is breaking Bitcoin's own finality, and that is exactly the boundary you should name. It ties to (4): the scheme's safety = Bitcoin's finality assumption, so set the lineage's finality to maxReorg and the "two mined branches" question answers itself.

(4) Confirmed-birth — maxReorg, not one. Birth is the genesis anchor the whole scheme rests on; it is one-time and attended, so the latency is cheap, and a 1-conf birth is a foundation a shallow reorg can unmake, leaving the enclave believing in a C_0 the chain dropped. Make the genesis as final as the deepest reorg you tolerate elsewhere. (Ongoing links can chain shallower / unconfirmed for throughput, with the reorg window handled by freeze + re-anchor — but the BIRTH is the one place to pay full finality.)

(3) Policy transitions — don't make it one global rule; split by direction, same asymmetry the mandate already uses (Tightening applies now, Loosening goes pending). A TIGHTENING (cancel, freeze, budget-down, rotate-to-safer) should apply AT ONCE — delaying protection to wait for a block is the wrong direction; a rollback of a tightening just returns to the looser prior state, which is the general rollback case your anchor already covers. A LOOSENING (budget-up, unfreeze, rotate-owner) is the dangerous direction and must be SPV-proved before it's live — make its activation = max(timelock height, SPV-confirmed height of its control-coin spend); the chain proof is the anchored twin of the timelock. So "apply after SPV" is right for loosenings; for tightenings, apply-at-once is not just acceptable, it's correct.

(5) Serialization — yes, safely relaxable: m FIXED lineages, the window budget PARTITIONED across them (shares summing to the total bound), gives m-way parallel throughput while the total-loss bound is unchanged. The anti-rollback property holds per lineage independently (a rolled-back enclave holds an old, spent coin on every lineage), and because the budgets are partitioned the sum is still the bound. Keep m fixed, changed only by an attended policy op; cost is m control UTXOs to manage. Use partitioned budgets, not a shared pool — a shared counter is probably still safe (the coins are the anchor, not the counter) but it needs its own proof; partitioned is provably safe by construction.

One synthesis worth putting in §3.4 for the owner: the control coin is the principled answer to the AUTO_ARM question. AUTO_ARM buys unattended restarts by DROPPING the bound; the control coin buys unattended restarts by MOVING the bound onto the chain. So for "the operator who cannot have a pause," the control coin is strictly better than AUTO_ARM — same unattendedness, bound intact. Three points on one spectrum: R7 (attended, simplest), control coin (unattended, bound kept, SPV+serialization cost), AUTO_ARM (unattended, bound forfeited, near-zero cost). That's the whole space, and it's a clean story to tell. No verdict needed — you see it all; these are the sharp edges.

## 6. R9 — the auditor's pre-review of the TPM-counter design (2026-11-05, recorded verbatim; the REQ-r9 skeleton)

R9 is the coherent move: it's source 3 from the taxonomy, and it's strictly simpler than the control coin (no SPV in the TCB, no serialization) while achieving the same thing the coin would — unattended restarts with the bound kept. With the provider accepted as residual, a vTPM is a legitimate source 3. Good call to drop the coin.

Core mechanism: sound. Your per-seal-not-per-load analysis is right — load-only lets the attacker copy a just-loaded fresh-counter blob, spend, restore, restart into a match; only a per-write bump makes the copy stale by restore time. And the counter check is anti-rollback by construction: the enclave demands certify(state.counter) == the live TPM value, a rolled-back blob carries a smaller stored counter, the TPM only certifies the live (higher) value → STATE_STALE. The nonce in qualifyingData kills certify replay; the AK sig kills a forged TPM; the host can only raise the counter (DoS), never lower it, so the reverse-tunnel agent exposing increment+certify is at worst a liveness DoS, never a rollback aid. All good.

Three edges to bake into the REQ before the questions:

1. HONEST SCOPE (the most important): R9's bound holds against root INSIDE the VM, not against the provider who owns the vTPM. State that wherever the bound is claimed, time-stable: "counter-backed bound holds vs VM-root; against the cloud provider it reverts to the hot-float, same as no counter." This is the V7/Nitro row made explicit — same discipline as the AUTO_ARM label. The physical-TPM / Azure-Trusted-Launch roadmap is what eventually closes it; until then the label travels with the claim.

2. R9 IS ADDITIVE TO R7, NEVER A REPLACEMENT. Build it so R7's owner-arm remains the fallback for every counter failure — crash between increment and seal, TPM lost, vTPM reset on migration, any mismatch. Then a lost TPM degrades gracefully to "attended R7," never to "bricked" and never to "funds unreachable" (the owner can always arm manually, and recovery-key still works). That graceful degradation is the resilience property that makes R9 safe to add: it only ever ADDS unattendedness when the counter matches; it never subtracts the owner's ability to arm.

3. The dev stand-in's liveness is NOT the product's. Per-seal over the laptop tunnel means the laptop must be reachable at every PAYOUT, not just every restart — far worse than R7's per-restart pause. That's a pure dev artifact: the product's local physical/vTPM has no network in the path. So the laptop drill validates the PROTOCOL (certify verify, counter logic, the vectors), not product liveness — don't let the tunnel's pain drive any product design decision, and name it exactly that in the REQ.

The four questions:

(a) Which ecalls certify — uniform: every blob-reading ecall verifies the certify, and every SEAL bumps. Don't carve out JUDGE/SIGN-only to save round-trips; that optimizes for the dev stand-in's pain, and the product TPM is local and cheap. The risk of carving out is a write path (APPLY_MESSAGE, HEADERS, POLICY) advancing state on a rolled-back blob the counter didn't guard — same completeness trap as C-R7-4. Note the charge/sign split: the counter bumps at the JUDGE seal (the charge), SIGN is read-only against the charged state so it only verifies (re-emitting the same sig is the same tx, harmless). If you must exempt pure reads (STATUS/REPORT), they must be labeled possibly-stale and never relied on for a freshness decision.

(b) AK trust — laptop verification (TOFU at init), strongly agree, same reason as the R6b YubiKey ruling: the enclave's contract is "a P-256 signature from the pinned AK over my nonce"; putting X.509 endorsement-chain parsing in the TCB is the hard-rule-6 violation we already rejected once. The owner verifies the TPM's endorsement on the laptop (where the tooling lives) and commits the AK pubkey into sealed state next to owner_pk — so the AK inherits owner_pk's trust root and lifecycle. One precision: because the AK is PINNED in sealed state, dev→product is NOT a pure R8 transport swap — the enclave code is unchanged, but the sealed state must carry the PRODUCTION TPM's AK, which is an owner re-init / re-anchor at deployment, not just pointing at a different socket. Say that plainly so it isn't mistaken for a config change.

(c) NV index lifecycle — define it as a true COUNTER index (TPMA_NV_COUNTER, so the TPM enforces monotonicity regardless of who holds increment auth); allocation is an attended setup at init/re-anchor. TPM loss = freshness lost → degrade to R7 (edge 2), never bricked. Re-anchor is an owner-signed, nonce'd message naming (AK, NV index, current counter value) and resetting state.counter; the nonce must make an old re-anchor (naming a stale index/value) refused after a rollback, exactly like R7's and the coin's re-anchor.

(d) TPMS_ATTEST parse TCB cost — acceptable, because it's a FIXED-LAYOUT struct read, not ASN.1/X.509. Keep it that way: a strict bounds-checked reader that pins magic (TPM_GENERATED), type (ST_ATTEST_NV), the nvName (== the pinned index), extraData (== your nonce), and reads the counter at its fixed offset; anything unexpected → STATE_STALE, never a panic inside the enclave. No dynamic allocation, no unbounded loops. P-256 verify is already in the TCB. Mutation-test the parser (truncated, overlong, wrong magic/type, wrong nvName, foreign nonce, non-AK signature → all refuse) — that's the break-test set, and it's your T0 vector list already, which is the right instinct.

Net: R9 is sound in shape and the right source-3 realization; the REQ should lead with the honest VM-root-not-provider scope and the R7-fallback resilience, and the four answers above are the sharp edges. Write it up and I'll DESIGN-PASS against this. No code before that, agreed.

