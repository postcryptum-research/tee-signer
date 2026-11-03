# REQ — R1 `signer-core` IMPL review

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r1-signer-core` at commit `e4afa1dbad02769bfb7f2e85e5d81b0b8ea8021b` (+ this REQ in the next
commit) of `github.com/77ph/BTCPayTEE`. **Requested verdict:** IMPL-PASS / CONDITIONAL / FAIL for
merging `core/` and `vectors/r1/` to `main`. Design of record: `RESP-design-2026-11-03.md`
(DESIGN-PASS CONDITIONAL) with its supplement. **Gates named for this round:** C-R4a–c, C-R5b, C-R6,
C-R10b, C-R12a/b/d/e (`CONDITIONS.md`).

## 1. What is on the branch

`core/` — the `no_std` + `alloc` trusted core, `#![forbid(unsafe_code)]`,
`#![deny(clippy::arithmetic_side_effects)]`; module map in `core/README.md`; crate closure with
provenance in `core/PROVENANCE.md`; vector format in `vectors/README.md`. No enclave shell yet (R2);
no host daemon (R2); no plugin (R3). Nothing is merged.

| Invariant | Where | How |
|---|---|---|
| I1 own input | `classify.rs` | only via a `bip32_derivation` hint whose in-enclave derivation reproduces the hinted key **and** `P2WPKH(pubkey) == prevout.scriptPubKey`; a hint that fails refuses (`INPUT_NOT_OWN`); no hint ⇒ foreign (never signed) |
| I2 amounts from the full previous tx | `classify.rs` | `non_witness_utxo` required for **every** input (own and foreign); txid recomputed and matched; a disagreeing `witness_utxo` refuses |
| I3 own output | `classify.rs` | verified hint on branch 0/1 with `index < bound + ownIndexGap`; a hint that does not reproduce the script refuses (`OUTPUT_SCRIPT_TYPE`); **no hint ⇒ unlisted** (charged) |
| I4 trusted | `wallet.rs::matches_trusted` | exact script, or derivation of `branches × gap` from the descriptor xpub |
| I5 outflow + caps | `judge.rs` | net = Σ own in − Σ own out (checked); per-tx and per-window per class; **fee ∈ net outflow**, every class counts toward `window.maxOutflow` (C-R5a/b) |
| I6 fee | `judge.rs`, `classify.rs` | `≤ maxFeeAbs`, `≤ maxFeeRate × vsize_lower_bound`, optional `maxFeePerWindow` |
| I7 structure | `classify.rs`, `judge.rs` | `SIGHASH_ALL` only (absent or 0x01; `ANYONECANPAY` refused), version 1/2, PSBT v0, unknown/proprietary fields refuse, duplicate outpoints refuse, RBF per rule, OP_RETURN explicit (C-R4c) |
| I8 payjoin | `judge.rs` | `none` ⇒ any foreign input refuses; `inflow-only` ⇒ foreign allowed only when own out ≥ own in; `outflow-allowed` ⇒ caps apply |
| I9 mandate | `state.rs`, `update.rs`, `mandate.rs` | P-256 verify over a domain-separated digest, nonce = installed + 1, network/wallet immutable, `validate`, checkpoint ≤ verified best, **classifier fails toward loosening** (C-R6) |
| I10 windows on headers | `state.rs::roll_window` | fixed windows from `start_height`, advanced by whole windows from the verified best; never backwards (the verifier itself is R4) |
| I11 commit → seal → sign | `judge.rs::Verdict::Accept { state, .. }` | the charged state (window usage, index bounds, `seq`) is returned for sealing before `sign_own_inputs` runs; receipts carry `seq` |
| I12 seed once | — | R2 (enclave shell); the core holds no secrets |
| R13 witness | `judge.rs` | token verified with the mandate's key; tip ∈ {best} ∪ recent within `maxTipLag`; `last_seen_seq ≤ seq` else **disarm** (`armed=false`, state returned for sealing) until `Rearm`; `Rearm` carries the owner nonce and adopts `max(seq, asserted)` (C-R13a) |

## 2. Evidence

- `cargo test` (std, host): 1 unit + **51 vectors** (`core/tests/vectors.rs`, written to
  `vectors/r1/*.json`) + 7 transition tests. `cargo test --features hollow-test`: + 4 mutation
  proofs. `cargo clippy --all-targets -- -D warnings` clean in both feature sets.
- **Both directions (C-R12a):** 9 accept vectors sign every own input, verify each signature against
  the recomputed BIP143 sighash, finalise, extract, round-trip the receipt and the state encoding;
  boundary pairs: unlisted at cap / cap + 1, net at `maxPerTx` / + 1, change index gap − 1 / gap,
  witness lag = `maxTipLag` / + 1, fee abs / + 1.
- **Mutation (C-R12b):** `hollow::i2_*` (drop the `non_witness_utxo` requirement ⇒ the
  lying-`witness_utxo` vector signs), `hollow::i3_*` (drop the output script check ⇒ change-to-
  foreign-key signs), `hollow::i5_i11_*` (drop commit-before-sign ⇒ the same tx signs twice past
  the window), `hollow::window_caps_*`. The knobs exist only under the `hollow-test` feature, which
  implies `std` and is never set for the enclave build; the release build gate (R2) asserts it.
- **C-R5b:** `refuse-trusted-at-max-fee-fee-counts-toward-window` — trusted-only destination, the
  fee alone pushes the window over ⇒ `CAP_WINDOW`.
- **C-R12e:** `refuse-overflow-sum-inputs` (u64::MAX + 1) and `refuse-overflow-sum-outputs` ⇒
  `OVERFLOW`, never wrap.
- **C-R6:** `classifier_fails_toward_loosening` — 26 field cases incl. "tighten one, loosen
  another" ⇒ loosening; witness key change ⇒ loosening; matcher change ⇒ loosening.
- Every R1-reachable refusal identifier has at least one vector (asserted by the suite).

## 3. Deviations from the design of record — please rule (supplement)

| # | Design said | Implemented | Why |
|---|---|---|---|
| D-1 | fee-rate check against an **upper-bound** vsize | **lower-bound** vsize | upper bound is the lenient direction (a fee too high for the real, smaller vsize would pass); lower bound can only refuse more. Docs corrected on the branch |
| D-2 | `non_witness_utxo` for own inputs | for **every** input | a foreign input's amount enters the fee computation; with `witness_utxo` only, a host could understate it. Net outflow was already safe (own amounts only); this closes the fee side too |
| D-3 | own outputs by derivation search within bound + gap | by **verified hint** within bound + gap; missing hint ⇒ unlisted | removes an unbounded-cost search from the enclave (each derivation is an EC multiplication) and keeps the decision cryptographic: the hint is a pointer, the match is the proof. A stripped hint can only make the enclave *over*-charge the budget (DoS), never admit value out. NBXplorer always supplies change hints |
| D-4 | own inputs by hint | same, plus **no fallback search**; an own coin without a hint is foreign (unsigned) | an input the enclave does not sign cannot spend the merchant's coin; with `payjoin = none` the whole tx refuses |
| D-5 | — | own **inputs** also raise the sealed index bounds | the enclave only learns receive indices from spends (receiving never touches it); without this a self-send to a recent receive index would refuse |
| D-6 | enabling the witness: unspecified | `required: false → true` (with a key) is **tightening**; changing the key is loosening | adding a precondition is restrictive; a swapped key could hide a rollback |
| D-7 | — | **any** update while a mandate is pending refuses (`POLICY_PENDING`), tightening included; cancel first | one in-flight change at a time keeps the timelock reasoning linear |
| D-8 | `Rearm { seq }` | `Rearm { nonce, seq }` adopts `max(own, seq)` | a Rearm can never lower the sequence (C-R13a) |
| D-9 | — | `Recover` voids pending mandate **and** pending owner rotation | the old owner key may be the thief's |
| D-10 | identity key: unspecified curve | secp256k1, compact 64-byte signature over `domain_digest("tee-signer/receipt/v1", receipt)` | one signing curve in the enclave's signing path; Bitcoin tooling verifies it |
| D-11 | — | descriptor matching derives up to `branches × gap` keys per unlisted-candidate output | cost noted (gap ≤ 1000); to be measured on hardware in R2 |

## 4. Known limits, stated

- The header verifier (R4) is not here: `state.chain` is set by the caller and treated as verified.
  Vectors set it directly; the enclave shell will only ever set it through the verifier.
- `hmac`/`rfc6979` enter the closure through `ecdsa`'s signing side (unused); `cpufeatures` through
  `sha2` (inert under `force-soft`). The objdump no-`cpuid` assertion (C-R10a) and `--gc-sections`
  are R2 build gates.
- secp256k1 context randomization: R2 (C-R10c).
- The secrets (seed, account xpriv, identity key) are not in `State`; the enclave shell seals them
  beside it (R2 REQ will show the blob layout).

## 5. Deliverable

`RESP-r1-signer-core-2026-11-03.md`: verdict and conditions, bound to the commit; committed verbatim
before any merge.
