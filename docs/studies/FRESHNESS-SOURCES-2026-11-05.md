# Where can a restarted enclave get the truth about "now"? — a study for the auditor

**Date:** 2026-11-05 · **Status:** a study, not a REQ — the owner asks the auditor to think along.
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
3. **An external counter the host cannot decrement**: a witness device (the freshness witness,
   developer tooling), or a TPM NV counter read through a TPM-signed certify with an enclave
   nonce. On a cloud VM the vTPM belongs to the hypervisor — it defends against root *inside* the
   VM, not against the provider, who is the adversary of scenario 3.

We do not see a fourth. The auditor is asked to find one or to confirm there is none.

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
  Until that transaction is **confirmed** (an SPV proof against the enclave's own header chain —
  a Merkle branch, ~1 KB), the enclave treats no control coin as live (auditor's point (4)).
- **Every signing.** A PSBT is judged only if one input is the current control coin and exactly
  one output recreates it at the next index; the enclave accepts as the next link any confirmed or
  unconfirmed transaction that spends the current coin and recreates the script (so RBF
  replacements do not strand the lineage — the full previous transaction is verified anyway).
- **Budget accounting** is charged against the lineage link that was mined, not per signed
  candidate (auditor's point (3)): two candidates for one link conflict on chain; one is charged
  when its successor's previous transaction names it.
- **Policy transitions** (install, update activation, cancel, rotate, recover) each spend the
  control coin in a tiny transaction carrying the message hash in `OP_RETURN`; the enclave applies
  the transition only after the SPV proof of that transaction. A rollback to a pre-tightening or
  pre-cancel state then holds a spent coin — equally dead. The owner, present for owner
  operations anyway, waits for that confirmation (one block).
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
