# REQ-r9a — the Anchor pins the LIVE counter: closing the anchor-window race (design REQ)

**Date:** 2026-11-18. **Status:** draft for the auditor (DESIGN-PASS wanted); the implementation waits for the
owner's scope decision (§5: a new MRENCLAVE, hence a ceremony signature and a new T2 wallet).
**Scope:** `core/src/state.rs` (`apply_anchor`), `enclave/rcore/src/ops.rs` (`apply_message`, the Anchor branch),
`core/src/reason.rs` (one new reason), vectors; the host daemon is unchanged. Builds on REQ-r9 (design + impl, both
PASSED 2026-11-10/11) and amends its §2.5.

## 1. The problem, as it happened

REQ-r9 §2.5: the owner's `Anchor` pins `expected = counter` — the value the owner saw in a `TPM2_NV_Certify` over
their own nonce — and the seal bumps it to `counter + 1`; the daemon increments the TPM after persisting
(`Daemon::persist`, `host/signerd/src/main.rs:267-290`). That is correct whenever nothing else persists between the
owner's `tpm-certify` and the Anchor's apply. But `persist()` increments on **every** durable blob, and the header
feed persists on **every** accepted block (`main.rs:509-514`); feed and owner ops are serialised under the daemon
lock, the owner's laptop round trip is not.

2026-11-18, `sgx-node-3`, the first anchor of wallet `7180f2b6` (UTC): 16:10:57 `tpm-certify` attests 7 → 16:11:03
block 331423, 16:11:14 the feed persists → TPM 8 → 16:11:32 the Anchor applies, `expected := 7`, seal → 8, persist →
TPM 9 → 16:11:34 the feed's next `HEADERS` is refused `STATE_STALE` (blob 8, TPM 9); every Fresh op since. A
legitimate owner anchor was made to look like a rollback by the daemon's own feed. Fail-closed, 0 funds at risk
(the wallet was empty), the cost a pause and a second anchor. Not caught by `e2e-local` / `e2e-tss-local` (no live
feed during their anchors) nor by the IMPL-PASS (the auditor's own note, 2026-11-18). REQ-r9 §2 row 5 named the
effect ("spurious increment → `STATE_STALE` → owner's Anchor"), not that the daemon's feed is a source whose remedy
re-opens the same window.

Scope of the window: anchoring a **live** state (a wallet's first anchor; a re-pin while payouts run). From
`STATE_STALE` the re-anchor is race-free: the feed's refusal returns no `HeadersResponse`, so nothing persists or
increments but the anchor itself (`main.rs:517-519`; the counter sat at 9 through 40 min of refusals).

## 2. The change

The Anchor stops trusting a static snapshot and takes the **live, attested** counter at apply time, with the
owner's attested value as a lower bound.

1. **Enclave shell (`ops.rs`, `apply_message`, the `Message::Anchor` branch).** The blob is still opened with
   `open_full_stale` — the Anchor remains the attended override and must not compare against the stale blob's
   `expected`. New: it takes the deposited proof (`session::tpm_proof_take()`; none → `TPM_REQUIRED`), decodes it
   (`TPM_PARSE`), verifies it with `tpm_attest::verify_nv_certify` against **the Anchor message's** `ak_pk` and
   `nv_name` and the **live nonce** (`TPM_SIG` / `TPM_INDEX` / `TPM_NONCE` as today), and obtains `live_counter`.
   The message's values, not the sealed ones: on a first anchor the blob has no anchor yet; on a re-pin to a
   replaced TPM the owner-signed values rule. Nonce and proof are consumed whatever the verdict (REQ-r9 Q5).
2. **Core (`state.rs`, `apply_anchor(msg, boot_challenge, live_counter)`).** All existing checks (owner signature,
   enclave id, next nonce, this load's challenge, `seq_seen ≤ seq`, well-formed material). New:
   `live_counter < msg.counter` → refuse with a new reason **`ANCHOR_COUNTER_BEHIND`** (a counter only moves
   forward; a value below what the owner saw certified is a lying host or a replaced TPM). Then
   `TpmAnchor.expected = live_counter` (the seal bumps to `live_counter + 1`; the daemon increments once after
   the persist → equal). The owner's value binds the authorization to a minimum state — the fix does not weaken the
   owner's control: between the owner's certify and the apply only the daemon's own persists can move the counter,
   each a state change the enclave itself sealed.
3. **No fallback.** A missing or failing proof refuses the Anchor. REQ-r9 §2.5's "Anchor without a proof"
   (found by the rollback drill) is replaced: the Anchor still bypasses the stale blob's comparison, but demands a
   verifiable live proof. A host without a transport cannot run R9 at all; with one, `call_fresh` already deposits
   a proof for every `APPLY_MESSAGE` (`main.rs:876`), so the daemon is unchanged.
4. **Freshness table.** `APPLY_MESSAGE` stays `Fresh`; the Anchor branch verifies the deposit itself instead of
   via `open_full_fresh`. `freshness_table_is_complete` unchanged.
5. **Host.** Unchanged. The optional host-side guard (refuse an Anchor whose `counter` ≠ the live read under the
   lock, with a clear message) is **not** adopted: redundant once (a) lands, never a boundary (auditor 2026-11-18).
6. **owner-cli.** Unchanged in behaviour; the printed prediction after `anchor` becomes "`tpm_expected` ≥ N+1".

## 3. Threat analysis (delta to REQ-r9 §2)

| Root in the VM does | Result |
|---|---|
| deposits the true live proof (counter ≥ the owner's) | applied; `expected` tracks the live counter — the race is closed to the daemon lock |
| deposits a proof with a counter below the owner's attested value | `ANCHOR_COUNTER_BEHIND` — impossible for an honest TPM (monotonic), so a lie or a replaced TPM |
| deposits a proof above the truth | cannot: the value is under the AK's signature (`TPM_SIG`) |
| replays an earlier proof | `extraData` ≠ the live nonce → `TPM_NONCE` |
| withholds the proof / the TPM | `TPM_REQUIRED` — the Anchor does not apply; the pause stays (REQ-r9 row 8) |
| restores an old blob and restarts | unchanged: `STATE_STALE`; the override still needs the owner's signature over this load's challenge and the next nonce |
| substitutes the TPM before setup/anchor | unchanged residual (THREAT-MODEL "TPM identity at anchor time") |

## 4. Vectors (T0: `vectors/r9a/` + `core/tests/replay.rs`; e2e: `scripts/e2e-local.sh`, `scripts/e2e-tss-local.sh`)

1. owner attests *N*, *k* feed persists before the apply (*k* = 1, 2): live *N*+*k* → applied, `expected`
   *N*+*k*+1, the next Fresh op is accepted (no `STATE_STALE`) — the 2026-11-18 case.
2. Anchor with no deposited proof → `TPM_REQUIRED`, state unchanged.
3. deposited counter < owner's → `ANCHOR_COUNTER_BEHIND`, state unchanged, proof consumed.
4. foreign AK / wrong Name / replayed nonce / truncated attest → `TPM_SIG` / `TPM_INDEX` / `TPM_NONCE` /
   `TPM_PARSE`, Anchor refused, proof consumed; the same Anchor again → `TPM_REQUIRED`.
5. the override still works: old blob expects *N*, TPM at *N*+*k*, owner's Anchor with a live proof → applied,
   `expected` *N*+*k*+1, armed; a proven `FREEZE` then goes through.
6. all REQ-r9 vectors unchanged (replayed Anchor → `POLICY_NONCE`, `seq_seen` ahead → `ARM_SEQ_BEHIND`, …).
7. e2e: the software transport gets a "feed persists *k* times inside the anchor window" knob; the anchor must
   apply clean. `e2e-tss-local`: the same against the laptop's PTT.

## 5. Consequences and rollout

- A new MRENCLAVE → the **ceremony** signs again (owner) → T2 redeploy as a new build → **a new wallet** on T2
  (sealing is MRENCLAVE-bound; FAQ "How do I move to a new enclave build"): the cheapest moment is **before the
  T2 wallet is funded** — `7180f2b6` holds 0 sat today. Owner cost: one init/quote/verify + mandate + anchor
  round (3× PIN + touch, one recovery passphrase), the retired record kept.
- Until it lands: the worked example re-anchors on a repeat (race-free from `STATE_STALE`); no host-image change
  for a case (a) closes.
- Docs: DESIGN §2.5/§10 (R9 row), REQ-r9 §2 row 5 (done 2026-11-18), THREAT-MODEL row (done), FAQ EN/RU (done),
  deploy/README (done); this file gets the RESP and the impl addendum.

## 6. Questions for the auditor

- Q1 the new reason's name: `ANCHOR_COUNTER_BEHIND` (one string in `reason.rs`), or reuse `STATE_STALE`? I prefer a
  distinct name: the owner must tell "my anchor was below the live counter" from "my blob is stale".
- Q2 verifying the deposited proof against the **message's** `ak_pk`/`nv_name` (owner-signed) rather than the
  sealed ones — agree? (No sealed anchor exists on a first anchor; on a re-pin the message's values must rule.)
- Q3 dropping the proof-less Anchor entirely (fail-closed `TPM_REQUIRED`) — agree?
- Q4 the host-side guard: skip (my proposal), or keep as a message for the owner?
