# REQ-r10-O01 — while the chain is frozen, a `PolicyUpdate` is a checkpoint re-pin or it is refused (design + impl REQ)

**Date:** 2026-11-21. **Status:** **DESIGN-PASS** at `28775df` → `RESP-r10-o01-frozen-update-design-2026-11-21.md` (same day; Q1 `ChainReorg` and Q2 pending-first agreed; v1 asserts the nonce is not consumed, v2b — an identical re-submit while frozen — added). Implementation on branch `r10-o01-frozen-update`, **SENT for IMPL-PASS** (same day) — §6 has what was run.

## 6. What was run (laptop, 2026-11-21, the implementation commit on the branch)

- `core`: fmt, clippy `-D warnings`, `cargo test` — green; transitions: 11 tests, the new
  `frozen_update_without_repin_is_refused` holds vectors 1 (tightening refused `CHAIN_REORG`, `nonce` still 0, the re-pin
  at nonce 1 accepted afterwards), 2 (loosening refused, nothing parks, the re-pin accepted), 2b (identical re-submit
  refused), 5 (unfrozen control: tightening at once, loosening pends), 6 (pending queued unfrozen → freeze → re-pin
  `POLICY_PENDING` → owner `Cancel` → re-pin applies, freeze ends, nonce 3); vectors 3–4 unchanged in the F-01 test,
  whose "ordinary path while frozen" tail is gone.
- `enclave/rcore` fmt/clippy/test (`nosgx,test-init`) green; `host/signerd --features nosgx` green; `fuzz` replay gate
  green (2181 inputs) and clippy green.
- Hollow red/green: `scripts/hollow-f01.sh` now 8 cases — the new one disables the O01 `if` (`if false`) and
  `frozen_update_without_repin_is_refused` goes RED; **8/8**, `core/src` restored clean.
- Placement as the RESP named: the `if` sits after the network/wallet checks and the `pending` check, before the
  checkpoint-changed branch and before `s.nonce = next`. **Origin:** the auditor's non-blocking observation in
`RESP-r10-f01-checkpoint-impl-2026-11-21.md` (carried in `REQ-r10-f01-checkpoint-impl-2026-11-20.md` §8); the owner's
go 2026-11-21 («следующие REQ — сейчас»). **Scope:** `core/src/state.rs` (`apply_message`, the `PolicyUpdate` arm:
one refusal), vectors, `POLICY.md`, FAQ; no wire change. `signer-core` changes ⇒ a new MRENCLAVE with the next
ceremony build. No `core/` code before this REQ's DESIGN-PASS (hard rule 1).

## 1. Today (`main` `fae6a84`, as deployed `2ae88422…`)

The `PolicyUpdate` arm, after signature / nonce / `pending.is_some()` checks:

- checkpoint **changed** while `chain.frozen` ⇒ the F-01 re-pin: checkpoint-only, applies at once, the chain
  restarts from the new checkpoint (C-F01-1/2);
- checkpoint **unchanged** while `chain.frozen` ⇒ falls through to `compare`: a `Tightening` installs at once
  (harmless — `judge` refuses `CHAIN_REORG` while the chain is frozen anyway — and useless); a `Loosening` goes to
  `pending` with `activation_height = best + timelock_blocks`, which **cannot be reached while frozen** (`best` is
  written only by `apply_headers`, which refuses every header while frozen), and from then on **every** later
  `PolicyUpdate` — including the re-pin that would end the freeze — is refused `POLICY_PENDING` until a `Cancel`
  (owner or recovery key) clears the pending.

Recoverable (`Cancel` → re-pin), so not a brick — the auditor's reading — but a trap: an operator's natural
"loosen the window while we sort this out" during a freeze parks the recovery behind a `Cancel` that nothing in
the status explains, and the tightening path is a no-op that still consumes a nonce.

## 2. Change

In the `PolicyUpdate` arm, when the chain is frozen and the new mandate's checkpoint equals the installed one,
refuse:

```rust
if s.chain.frozen && new.checkpoint == s.mandate.checkpoint {
    // the chain is frozen by a deep reorg: the only policy update that helps is a checkpoint re-pin
    // (REQ-r10-O01); a tightening would be a no-op behind CHAIN_REORG and a loosening would park in
    // `pending` for ever (best is pinned while frozen) and block the re-pin itself behind POLICY_PENDING
    return Err(Reason::ChainReorg.into());
}
```

placed **after** the `pending.is_some()` check (Q2) and before the checkpoint-changed branch. Result: while the
chain is frozen the **only** accepted `PolicyUpdate` is a checkpoint-only re-pin — the frozen path has exactly one
shape. Everything else is untouched: `Cancel` keeps clearing a pending (the documented recovery when a pending was
queued before the freeze), `Unfreeze`/`Rearm`/`RotateOwner`/`Recover`/`Arm`/`Anchor` do not look at the chain,
`activate_pending`'s frozen branch (a pending with a changed checkpoint activating while frozen) stays as is.

- **Q1 — the reason code.** `ChainReorg` (`CHAIN_REORG`: the reason `judge` already gives for a frozen chain; it
  names the cause and the remedy, no new wire code) — the dev's pick — or `PolicyInvalid` (the generic refusal of
  the arm)?
- **Q2 — order with `POLICY_PENDING`.** Pending check first (as drafted): with a pending in flight the operator
  learns "cancel first", then the re-pin is accepted. The alternative (frozen check first) would hide the pending
  behind `CHAIN_REORG` and the operator's re-pin would then hit `POLICY_PENDING` anyway.

Not changed by this REQ, named for the record: a freeze that happens with a pending already queued (queued
unfrozen) keeps that pending; it cannot activate while frozen; the sequence is `Cancel` → re-pin — an owner step,
documented (§4).

## 3. Vectors (`core/tests/transitions.rs`)

1. frozen, checkpoint unchanged, a tightening elsewhere ⇒ `CHAIN_REORG`, nonce not consumed, chain still frozen,
   mandate unchanged (replaces the current tail of `frozen_repin_applies_at_once_and_is_checkpoint_only`, which
   documents today's "takes the ordinary path" and flips);
2. frozen, checkpoint unchanged, a loosening ⇒ `CHAIN_REORG`, `pending` stays `None`;
3. frozen, checkpoint-only re-pin (same height / forward) ⇒ applies at once (vectors 12–13 of REQ-r10-F01, kept);
4. frozen, re-pin plus another field ⇒ `POLICY_INVALID` (vector 14, kept);
5. control: unfrozen, the same tightening ⇒ applies at once, the same loosening ⇒ pending;
6. a pending queued unfrozen, then the chain freezes, then a re-pin ⇒ `POLICY_PENDING`; `Cancel` ⇒ the re-pin applies
   and clears the freeze — the documented recovery sequence, end to end;
7. hollow red/green: `scripts/hollow-f01.sh` gains the case "O01 refusal removed ⇒ vectors 1–2 go green" (RED
   required), so every protection site on this path stays mutation-proven.

Fuzz: the F4 structured target of phase 2 (`REQ-r10-fuzzing-phase2-design-2026-11-21.md`) carries the invariant
"while frozen, `apply_message(PolicyUpdate)` is `Ok` iff it is a checkpoint-only re-pin" — before and after this
REQ its two halves are the oracle.

## 4. Documents

- `POLICY.md`, `chain` section: "While the chain is frozen the only policy update accepted is a checkpoint re-pin
  (checkpoint-only, applies at once); any other update is refused `CHAIN_REORG`. A pending update queued before the
  freeze must be cancelled first (`Cancel`, owner or recovery key)."
- `docs/FAQ.md` / `docs/FAQ_ru.md`: the frozen-chain recovery sequence as an owner step (status shows
  `chain_frozen`; if a pending exists, `Cancel`; then a re-pin to a header of the live chain; nothing else is
  accepted until then).
- `THREAT-MODEL.md`: no change (liveness, not a security boundary).
- `deploy/README.md`, T2 row: until the next ceremony build the deployed `2ae88422…` carries this trap — labelled as
  a known liveness trap with the documented `Cancel` → re-pin recovery, not as a defect.

## 5. Consequence

`signer-core` changes ⇒ MRENCLAVE changes ⇒ the next ceremony build (owner), the auditor's decorrelated build as the
content gate, the R9a/F-01 migration procedure (a new wallet; the live `1a36ada6` has 0 sat). No wire change
(`State::encode` untouched). Implementation on branch `r10-o01-frozen-update` after DESIGN-PASS; IMPL-PASS before
merge.
