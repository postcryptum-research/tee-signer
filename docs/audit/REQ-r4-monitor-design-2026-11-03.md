# REQ — R4 design: the owner's monitor — chain observation first, receipts second, freeze as the reflex

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r4-monitor` of `github.com/77ph/BTCPayTEE`. **Requested verdict:** DESIGN-PASS / CONDITIONAL /
FAIL. **Gates this round carries:** C-R2-2 / C-R3-1 (cross-restart seq-fork detection, receipt
authenticity, chain observation primary — the named gate for any "enforce" on value), D-R3-4,
the feed-stall class from R5 §5a (cookie rotation, tip lag), C-R12c's `maxTipLag` boundary in
use. **No TCB change is proposed.** The enclave already produces identity-signed receipts keyed
by `(session_id, seq)`, carries the freshness precondition (`POLICY.md §freshness`:
`FRESHNESS_MISSING/SIG/TIP/SEQ_BEHIND`), and accepts an unsigned `FREEZE` from anyone. The monitor
is owner-side code that consumes those — on the operator machine (dev: this laptop), never on the
BTCPay box, with its own chain source.

## 1. What the monitor is for, in one sentence each

1. **A spend the enclave did not receipt is the alarm.** The wallet's coins moving on-chain with
   no matching receipt means a signature the owner cannot account for — a forked blob replayed, a
   stolen seed, a bug: the chain is the ground truth, the receipt log is the claim.
2. **A receipt that does not verify, or a `seq` that regresses or repeats, is the alarm.** Within
   one session or across sessions: a duplicated `seq` is the seq-fork signature (R2 §4a).
3. **A feed that stops is a warning that becomes an alarm.** The enclave's best header falling
   behind an independent tip by more than `maxTipLag` (the cookie-rotation class: fail-closed in
   the enclave, invisible from inside).
4. **The reflex is FREEZE** — unsigned, allowed to anyone, and a tightening: the monitor needs no
   key to stop the signer. Un-freezing needs the owner's key (TPM) after a human looks.

## 2. Inputs and trust

| Input | Source | Trust |
|---|---|---|
| wallet record | `wallet.json` (xpub, fingerprint, identity_pk, enclave_id, MRENCLAVE/MRSIGNER pins, mandate caps) | the owner's |
| receipts, status | `signerd` `/v1/receipts`, `/v1/status` through the owner's tunnel | **untrusted** (the host); receipts are believed only after the identity signature verifies |
| chain | an **independent** source — the owner's own node (read-only RPC) or a public Esplora (`mempool.space/signet`); never the signer host's node | the ground truth; two sources may be configured and must agree on the tip |
| witness key | `--witness-key` (keyfile or `tpm:` locator) when `freshness.required` | the owner's |

## 3. The loop (every `--interval`, default 60 s; one pass = one verdict)

1. **Receipts.** Fetch all; for each: decode, verify `receipt_sig` with `identity_pk` (an invalid
   signature ⇒ ALARM `RECEIPT_SIG`); check `enclave_id`; order by `(session_id, seq)`:
   `seq` must increase by exactly one within a session; across a session change the next `seq`
   must be the previous session's last + 1 (a benign restart, INFO); **any duplicate `seq`** (two
   receipts, same `seq`, different `txid`) or regression ⇒ ALARM `SEQ_FORK`.
2. **Chain.** Derive the wallet's scripts (branches 0 and 1 up to the gap the mandate uses +
   `ownIndexGap`); from the chain source list every transaction that **spends** one of them (confirmed
   and mempool); for each spending `txid` require a verified receipt with that `txid` ⇒ otherwise
   ALARM `SPEND_WITHOUT_RECEIPT` (primary detection). A receipt whose `txid` never appears
   on-chain within `--receipt-grace` blocks is INFO (BTCPay may not have broadcast; not a security
   event).
3. **Accounting cross-check.** Sum per-window outflow from the chain against the mandate's caps
   independently of the enclave ⇒ an overrun is ALARM `CAP_EXCEEDED` (the enclave would not do this;
   if it happens, the enclave is not the one signing).
4. **Feed.** `status.best_height` vs the independent tip: lag > `maxTipLag` ⇒ WARN `FEED_STALL`,
   persisting for `--stall-alarm-after` passes ⇒ ALARM; `status.chain_frozen` ⇒ ALARM `CHAIN_REORG`
   (the enclave froze itself on a deep fork — the owner must re-pin).
5. **Liveness.** `signerd` unreachable for N passes ⇒ WARN (not an alarm: an attacker who stops
   the daemon stops signing too); `session_id` changed ⇒ INFO with the seq-continuity check of (1).
6. **Freshness (when the mandate requires it).** Issue a `WitnessToken { tip_hash, tip_height,
   last_seen_seq, issued }` signed by the witness key and submit it — so a signer that was rolled
   back behind the monitor's `last_seen_seq` refuses with `FRESHNESS_SEQ_BEHIND` (C-R12c). The token
   is the monitor's own view, never copied from the signer.
7. **Attestation (T2, optional, `--attest-every`).** Re-run the seven-step verifier; a failure ⇒
   ALARM `ATTEST`.
8. **Reflex.** On any ALARM: `POST /v1/freeze` (unsigned), write the alarm record, exit non-zero
   (or keep running with the alarm latched, `--keep-running`), and notify (`--webhook`, a
   plain POST; email/Telegram are the operator's choice). WARN never freezes.

Output: an append-only JSONL journal (`monitor.jsonl`) of every pass with the tip, the enclave's
best, the receipt high-water mark `(session_id, seq)`, the chain's spend set hash, and the verdict;
the state the monitor needs across runs is only that high-water mark (so a restart of the
monitor cannot "forget" a seq it has seen — it is written before the pass's verdict).

## 4. What it does not do, said plainly

It does not prevent a seq-fork; it detects it within one pass (bounded by the detection latency
`interval` + chain propagation), which is the bound stated in `ENCLAVE.md §4a`. It does not replace
the enclave's accounting; it cross-checks it from the chain. It is not in the TCB and cannot be:
it runs on the owner's machine with the owner's chain source, which is exactly why its alarm is
believable.

## 5. Evidence the IMPL REQ will carry (executed on signet, T2 and T1)

Positive: a normal payout → receipt verified, spend matched, no alarm. Negatives, each executed:
(a) a spend without a receipt — simulated by replaying a previously signed-but-unbroadcast
transaction from a copy of a sealed blob taken before its JUDGE (the seq-fork shape from R2's
`TEST_RESET_SESSION` on T1) ⇒ `SPEND_WITHOUT_RECEIPT` or `SEQ_FORK` and a freeze within one pass;
(b) a tampered receipt line ⇒ `RECEIPT_SIG`; (c) a duplicated `seq` in the receipt log ⇒
`SEQ_FORK`; (d) a stalled feed (the cookie case reproduced by rotating the node's cookie) ⇒
`FEED_STALL` then ALARM; (e) freshness: with `freshness.required` on a test mandate, a signer
behind the witness's `last_seen_seq` refuses `FRESHNESS_SEQ_BEHIND`; a stale token refuses
`FRESHNESS_TIP`; (f) the monitor restarted mid-way keeps its high-water mark.

## 6. Decisions to rule

- **D-R4-1** FREEZE as the automatic reflex on ALARM (no key, tightening); WARN never freezes.
- **D-R4-2** the chain source must be independent of the signer host; a public Esplora is
  acceptable for signet/dev, the owner's node for value; two sources optional and must agree.
- **D-R4-3** the monitor runs on the operator machine (laptop) or any owner-controlled host,
  never on the BTCPay box; its state is the receipt high-water mark only.
- **D-R4-4** duplicate `seq` across sessions = ALARM even when the txids are the same? No:
  identical `(seq, txid)` twice is the idempotent re-sign (R2); **different txid, same seq** is
  the fork. Confirm.
- **D-R4-5** witness tokens issued every pass when freshness is required (cadence = interval);
  `last_seen_seq` = the verified high-water mark, never the signer's claim.
- **D-R4-6** the monitor is a subcommand of `owner-cli` (`owner-cli monitor run`) sharing the
  wallet record and key locators — versus a separate binary.
