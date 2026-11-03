# REQ — R4 IMPL: the owner's monitor, executed on signet against the T2 signer

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r4-monitor` of `github.com/77ph/BTCPayTEE` (commit named in the sending message). **Design of
record:** `REQ-r4-monitor-design` + `RESP-r4-…` (DESIGN-PASS; C-R4-1..5; C1/C2 confirmed by you
firsthand). **Requested verdict:** IMPL-PASS / CONDITIONAL / FAIL for merging to `main`. **Closes
(on IMPL-PASS):** C-R2-2 (cross-restart seq-fork detection), C-R3-1 (receipt authenticity +
chain observation), D-R3-4, the R5 §5a feed-stall class; advances C-R4-1..5. **TCB:** `git diff
main -- core enclave` is **empty**; the branch is `owner/owner-cli` (`src/monitor.rs` + the
`monitor` command, `psbt-build --prev-tx-hex`).

## 1. What was built — `owner-cli monitor` (`owner/owner-cli/src/monitor.rs`, ~560 lines)

| Step | Implementation | Codes |
|---|---|---|
| receipts | `GET /v1/receipts` (untrusted) → each line: decode, `enclave_id` must match, **identity signature verified** (`verify_digest_secp` over `Receipt::digest()`), the host's line fields must agree with the signed receipt | `RECEIPT_SIG` |
| `(session, seq)` discipline | same seq + different txid ⇒ fork; max seq below the stored HWM or a previously verified txid gone ⇒ regression; missing seqs ⇒ gap (WARN; the chain check covers their spends); session change with continuity ⇒ "benign restart" note | `SEQ_FORK`, `SEQ_REGRESSION`, `RECEIPT_GAP` |
| HWM | `(session_id, seq, verified txids)` written to `<journal>.hwm.json` **before** the verdict; monotone | — |
| chain (primary) | **the owner's node** (`--node-rpc/--node-cookie`): `scantxoutset` over `wpkh(xpub/{0,1}/*)` with range `(hwm_seq+1)×(ownIndexGap+1)` (C-R4-1) on the first and every `full_every`-th pass, a walk of every block since the last pass (first pass: the last `window` blocks) matching inputs against every output ever known as ours and outputs against our addresses, and `gettxspendingprevout` for the mempool; **or** an Esplora (`--esplora`, throttled, 429/transport backoff, address cache with periodic full scans) — signet/dev only (C-R4-3) | `SPEND_WITHOUT_RECEIPT`, `RECEIPT_AMOUNT` (claimed vs observed net outflow), `CHAIN_SOURCE` (WARN, checks skipped, never a dead monitor) |
| cap accounting from the chain | net outflow of spends in the last `window.blocks` vs `limits.window.maxOutflow`, independent of the enclave's own numbers (C3) | `CAP_EXCEEDED` |
| feed | enclave `best_height` vs the source's tip: lag > `maxTipLag` (or `--max-tip-lag`) ⇒ WARN, after `--stall-after` consecutive passes ⇒ ALARM; `chain_frozen` ⇒ ALARM | `FEED_STALL`, `CHAIN_REORG` |
| liveness | signerd unreachable ⇒ WARN only | `SIGNERD_UNREACHABLE` |
| freshness | when the mandate requires it: a `WitnessToken { tip_hash, tip_height, last_seen_seq = the monitor's HWM, issued }` signed by `--witness-key` (keyfile or `tpm:` locator) and submitted every pass; missing key ⇒ WARN | `WITNESS_REFUSED`, `WITNESS_KEY_MISSING` |
| reflex | any ALARM ⇒ `POST /v1/freeze` (unsigned); `--no-freeze` for tests; WARN never freezes | — |
| heartbeat | one JSONL line per pass (`verdict, codes, tip, enclave best, HWM, counts, outflow, froze, notes`); `--once` exits 0/1/2 | C-R4-5 |

Unit tests (`cargo test monitor`, synthetic receipts signed by a throwaway identity key): genuine
receipts verify + sequence with a benign restart; a tampered receipt ⇒ `RECEIPT_SIG`; a host line
disagreeing with its receipt ⇒ `RECEIPT_SIG`; same seq + same txid idempotent, same seq +
different txid ⇒ `SEQ_FORK`; a shrunk log ⇒ `SEQ_REGRESSION`; a foreign enclave id ⇒ refused.

## 2. Executed on signet — the live T2 wallet (Azure), the Hetzner dev node as the chain source

The chain source is the owner's own signet node on the Hetzner box (reached through the owner's
tunnel), i.e. **not** the host of the T2 signer; a public Esplora was tried first and rate-limited
the full scan into failure (`CHAIN_SOURCE` WARN, the monitor kept its heartbeat) — which is C-R4-3
measured, not argued.

| Vector | Result (journal lines in `.local/signet-t2/monitor.jsonl`) |
|---|---|
| positive, first pass | `OK … receipts 3 spends 3 outflow 11065 sat` — 3 receipts verified, 3 on-chain spends each matched to a receipt, UTXO set + 144 blocks walked (2 m 17 s); the incremental pass: 1 s |
| (b) receipt tampered on the host (one byte of a signature) | `RECEIPT_SIG` (line 1, claimed seq 2) + `SEQ_REGRESSION` (a previously verified txid gone) + `RECEIPT_GAP` + **`SPEND_WITHOUT_RECEIPT`** for the now-unreceipted on-chain spend `2c230c06…` ⇒ **ALARM, FREEZE sent, signer frozen**; owner restored the log and unfroze with the owner key ⇒ next pass `OK` |
| (a) receipt withheld (the host dropped the last line; the spend `67d68ef1…` stays confirmed on-chain) | `SEQ_REGRESSION` (max seq 2 < HWM 3; the txid gone) + **`SPEND_WITHOUT_RECEIPT`** ⇒ ALARM, FREEZE; restored + unfrozen ⇒ `OK` |
| (e) freshness, on a throwaway T2 wallet with `freshness.required=true`, a witness keyfile, funded from T2 under T2's mandate (txid `ad54a901…`, T2 seq 4), headers fed to the tip | **no token ⇒ `FRESHNESS_MISSING`**; the monitor issues a token from its own view (tip 329301, last_seen_seq 0) ⇒ **signature ACCEPTED** (seq 1, `52c35b58…`); a stale token (tip 12 blocks back) ⇒ `FRESHNESS_TIP`; a token with last_seen_seq 5 > the enclave's 1 ⇒ `FRESHNESS_SEQ_BEHIND` |
| (d) feed stall (the T2 node's `bitcoind` stopped 19:53 UTC; signet block 329302 arrived ~20:17) | `ALARM … FEED_STALL — enclave best 329301 is 1 blocks behind the chain tip 329302 (limit 0); 1 consecutive passes` ⇒ FREEZE (with `--stall-after 2`: WARN would precede; run with the limit at 0 to show the ALARM); second pass same; operator restarted the node, the feed caught up in one round (`headers fed n=1`, enclave best 329302), owner unfroze ⇒ `OK` |
| (g) a standing alarm after review | the thief's spend stays in the mempool, so every pass re-alarms and re-freezes — correct, and unlivable without a human decision: **`--acknowledge <txid>`** (persisted beside the journal) records that the owner reviewed that spend; the next pass is `OK` with the note "spend without receipt, acknowledged by the owner" (D-R4-9) |
| (f) restart keeps the HWM | passes 1 → 12 across separate invocations; the HWM file carries `(51cf9562…, 3)` and the verified txids; the shrunk-log vector is exactly the HWM doing its job |

**The seed-leak vector, executed** (the owner printed the mnemonic themselves with
`recovery-verify --print-mnemonic` and handed it over; `tools/seed-leak-vector` — a test instrument
outside the product — turned it into the BIP84 private descriptors, fingerprint `fae69580` = the
T2 wallet's; imported into a throwaway descriptor wallet on the owner's Hetzner signet node; the
thief saw the T2 balance, 23 435 sat, and spent 3 000 sat with `sendtoaddress`, txid
`47ddc1e1…fd95`, no enclave involved):

- **first pass: `OK` — the gap.** The thief spent the T2 wallet's *unconfirmed change* (the
  output of the funding transaction `ad54a901…`, still in the mempool). The monitor's node source
  learned "our outputs" from the UTXO set (confirmed only) and from block walks, so an output our
  own enclave had just created, not yet mined, was unknown to it and a spend of it invisible.
  Found by this vector, nothing else would have shown it.
- **fix (same branch):** every receipted transaction not yet confirmed is read from the node and
  its outputs to our addresses noted, so the mempool spender check covers them.
- **second pass: `ALARM … SPEND_WITHOUT_RECEIPT` — `47ddc1e1… spends 3282 sat of the wallet (in the
  mempool) and no verified receipt names it` — FREEZE sent, signer frozen.** Owner unfroze after
  looking. The throwaway node wallet was unloaded and its files deleted; the derived descriptors
  deleted from the laptop; the mnemonic exists in the owner's terminal history and this
  conversation — it is the signet dev wallet's, and the owner knows.

A remaining labeled edge: an output paid to us by a *third party* that is still unconfirmed is
likewise unknown until mined; a thief spending it before confirmation would be seen one pass
after the funding confirms (the block walk notes the output, the spend is then in the mempool or
a later block). Closing it fully means scanning the mempool for outputs to our addresses every
pass (`getrawmempool` + per-tx reads) — cheap on signet, a cost question on mainnet; labeled.

**Two models, named apart (the owner's rule, 2026-11-03):** the **threat model** (compromise:
adversary, detection, prevention — attack vectors) and the **continuity model** (accidents: lost
enclave, disk, laptop, keys — recovery drills; `docs/CONTINUITY.md`, new on this branch). The
monitor, the mandate and attestation belong to the first; the recovery blob, the recovery key and
`--print-mnemonic` to the second. The seed-leak vector below sits in the first only as detector
mechanics; the restore it incidentally performed is logged in the second as a drill done in the
wrong frame (online laptop, words in a chat) — the proper D2 drill is still owed.

**What the seed-leak vector is and is not (the owner's point, 2026-11-03):** a leaked seed is a
total loss by definition — any HD wallet restores it and spends everything; no enclave, mandate,
monitor or freeze undoes that, and the monitor's FREEZE stops the enclave, not the thief. The
vector therefore proves only the detector's mechanics (a spend the enclave did not receipt is
seen), not a defence. The design's one and only defence against this class is that the seed
never leaves the enclave except into the recovery blob encrypted to an offline recovery key, and
that printing it is an explicit, warned, confirmed act for an actual restore. The monitor's real
value is the other classes, where the enclave is still the only signer and the freeze does stop
further damage: tampered or withheld receipts, a seq-fork across a restart, a stalled feed.

**A benign restart, observed:** across the ceremony-signed redeploy the receipt for seq 4 carries
a new `session_id` (`51cf9562…` → `02ddb6dd…`) with seq continuity; the monitor reported it as the
design says ("session changed … with seq continuity (benign restart)"), not as a fork.

## 3. Labeled

- A public Esplora is not a chain source for this monitor beyond toy wallets (C-R4-3 measured).
- The Esplora path's incremental scan re-reads addresses with history plus the live window;
  completeness is re-established by the periodic full scan; the node path is complete every pass
  by construction (`scantxoutset` + block walk).
- The node source needs `gettxspendingprevout` (Bitcoin Core ≥ 24) for mempool spends.
- Witness cadence = the interval; the operator sets `--interval` ≤ the mandate's `maxTipLag` in
  wall-clock terms (C-R4-4), or signing starves under `freshness.required`.
- The monitor's own liveness: the journal's last line (C-R4-5); a webhook is the operator's choice.

## 4. Decisions to rule

- **D-R4-7** `RECEIPT_AMOUNT` (claimed vs chain-observed net outflow) is a WARN, not an ALARM
  (a receipt that verifies cannot be forged; a mismatch means the enclave's accounting and the
  monitor's disagree on what is "ours" — worth a human, not a freeze). Confirm.
- **D-R4-8** `RECEIPT_GAP` is a WARN (a withheld receipt is caught by the chain check as
  `SPEND_WITHOUT_RECEIPT` the moment its spend appears). Confirm.
- **D-R4-9** `--acknowledge <txid>`: a reviewed spend-without-receipt stops re-alarming; the
  acknowledgement is persisted and journaled as the owner's decision. Without it the reflex would
  re-freeze every pass after every unfreeze. Confirm the shape (per-txid, explicit, logged).
