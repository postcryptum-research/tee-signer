# REQ-r10 phase 2 (design) — structured fuzzing of the policy core: state operations, headers, PSBT classification, the judge and `disarms`, the dispatcher

**Date:** 2026-11-21. **Status:** SENT for DESIGN-PASS (phase 2 of `REQ-r10-fuzzing-design-2026-11-20.md`, DESIGN-PASS
CONDITIONAL; phase 1 IMPL-PASS `RESP-r10-fuzzing-impl-2026-11-20.md`). **Owner's go:** 2026-11-21. **Binds:** C-R10-4
(`disarms` exact), C-R10-6 (work no-wrap), C-R10-7 per class (a)/(b), C-R10-F; the RESP-r10 rulings C4/C6 and "F10 =
the C-R9-C table + direct invariants, no state-machine model". **Scope:** the `fuzz/` crate only — targets, seeds,
dicts, limits, `injected-defects.sh` cases; `core/` and `enclave/` untouched by the harness. Nothing implemented
before DESIGN-PASS.

## 1. Targets and oracles

Conventions of phase 1 unchanged: one body per target (`fn(&[u8])`), `arbitrary::Unstructured` for the structured
generators, honest objects from `core/tests/common` (`#[path]`), every assertion names its oracle, `seeds/` by hand,
`corpus/` grown and `cmin`'d, `regressions/` must pass, `findings/` must still fire, the stable replay gate as CI,
laptop runs only.

| Target | Design row | Input | Oracles |
|---|---|---|---|
| `state_ops` | F4 | the fixture state (`init_state`), then ≤ 24 `arbitrary`-driven steps; a step is one of: `PolicyUpdate` (a structured mutation of the installed mandate, honestly signed by the owner key; 1 in 8 signed by the wrong key or mutated after signing), `Cancel` (owner or recovery), `Unfreeze`, `Rearm`, `RotateOwner`, `Recover`, `Arm`, `Anchor` (an honest attest for a chosen counter), a header feed (regtest headers mined from the fixture checkpoint — the F6 generator — to advance `best`), a chain freeze (a reorg deeper than `max_reorg` from the same generator) | **never a panic**; `apply_*` is `Err` for every message that does not verify under the right key (C-R10-3 reused); an accepted owner message advances `nonce` by exactly one and a refusal does not consume it; at most one `pending` and one `pending_owner`; a `Loosening` never installs before `best >= activation_height` and installs on the first op at or after it; a `Tightening` installs at once; while `chain.frozen`: `PolicyUpdate` is `Ok` **iff** it is a checkpoint-only re-pin, and the re-pin resets the chain and clears the freeze (C-F01-1/2; after REQ-r10-O01 the "only if" half becomes a refusal `CHAIN_REORG`); a freeze taken unarmed persists through `Arm` (C-R7-6); **the installed mandate validates after every step** (the C-F01-3 invariant, live); `State::decode(State::encode(s)) == s` after every step (C-R10-2 on the live state); `compare(installed, new)` agrees with the install outcome |
| `headers` | F6 | a state decoded from fuzz bytes **or** derived from the fixture with `arbitrary` values of `best.work`/`recent[].work` (the no-wrap oracle needs near-2^256 work: the sealed blob is the enclave's own, but the arithmetic discipline is the oracle), then ≤ 8 header batches from a generator that mines on the fixture chain: regtest params (no retarget) and signet params (the real 2016-period retarget; `vectors/headers/signet-322560-324700.hex` as seeds), with `arbitrary` forks at any depth, mutated `bits`/`time`/`prev`/`version`, batches split at arbitrary points, duplicate and out-of-order headers | never a panic; `best` never moves to less cumulative work (the LE 256-bit compare of `best.work` is monotone over accepted batches); **C-R10-6**: for every accepted header `work(child) > work(parent)` and a batch that would overflow is refused `OVERFLOW` — never a wrapped value (the generator plants work near `2^256`); a reorg deeper than `max_reorg` ⇒ `chain.frozen` **and** `CHAIN_REORG`, and frozen stays frozen (every later batch refused); the return value equals the main-chain growth; `recent` is contiguous, ends at `best`, bounded by `max_reorg + RECENT_EXTRA` and `MAX_RECENT`; `period_start_time`/`period_bits` equal the generator's ground truth for the current period (so leg 2 of F-01 pins against correct values); per-network rules of C-R3a (min-difficulty on testnet4, powLimit) hold on the generator's cases |
| `classify` | F7 | mode 0: raw PSBT bytes (`MAX_PSBT`); mode 1: a structured PSBT from a `build_psbt`-equivalent generator driven by `arbitrary` — own/foreign inputs with or without `non_witness_utxo`, a **lying** `witness_utxo` amount, own/trusted/unlisted/foreign/OP_RETURN outputs, hints present/absent/wrong, index at and beyond `own_index_gap`, versions, sighash types, `nSequence` | never a panic; `Ok` ⇒ every `Own` input has a `non_witness_utxo` whose txid equals the outpoint's and whose output amount is the one counted (I2) — the lying `witness_utxo` never is; every `Own` output's script equals the derivation from the account key at the claimed path (I3); Σ amounts never wraps (`OVERFLOW`, with the generator planting amounts near `u64::MAX`); the own-index bound is respected (index ≥ bound ⇒ not `Own`); an unknown script type or sighash ⇒ `Err`, never an `Ok` with an unknown class (fail-closed); **"the host never decides"**: flipping any host-asserted field that does not change the cryptographic facts (a hint's presence, a `witness_utxo` value, a marker) never turns an `Err` into an `Ok` and never changes a counted amount |
| `judge` | F8 | a `Classified` from the F7 generator + `arbitrary` state knobs: window counters, caps, heights, `frozen`/`armed`/`chain.frozen`, `not_after_height`, freshness required with an honest, mutated, tip-lagging or seq-behind witness token | never a panic; `Accept` ⇒ every cap holds (per class per tx, window, `fee_abs`/`fee_rate`/fee-window, gap, `maxTipLag`), the charge equals the accepted amounts and never decreases a window; `Refuse` carries ≥ 1 reason; `frozen`/expired/unarmed/`chain.frozen`/stale ⇒ never `Accept`; **C-R10-4, both directions**: `disarm.is_some()` **iff** the refusal is the rollback-suspected case — a witness token that verifies under the mandate's witness key and carries `last_seen_seq > s.seq` (`judge.rs:170`) — never on any other refusal (an unverified token, tip lag, caps, frozen) and always on that one; judging twice equals judging once (`activate_pending`/`roll_window` idempotent) |
| `dispatch` | F10 | `rcore::ops::dispatch` under `nosgx,test-init`: (a) arbitrary op code + arbitrary bytes, incl. an arbitrary "sealed blob" ⇒ `STATE_UNSEALABLE`, never a panic; (b) sequences: `TEST_INIT` with a fixed seed, then ≤ 16 steps of (`op`, payload) where payloads are honest encodings with `arbitrary` mutations; `TEST_RESET_SESSION` per sequence | every `Response` decodes (proto round trip, C-R10-2); **the blob changes only through a `Fresh` op** of the `FRESHNESS` table (C-R9-C): the sealed-blob hash before/after a `Stale`/`NoBlob` op is identical; after a TPM-bound state every `Fresh` op without a deposited proof is refused (`STATE_STALE`/`TPM_REQUIRED` as the table says); `SIGN` returns a signature only for the PSBT the preceding `JUDGE` accepted byte for byte, and then `seq` advances by exactly one; direct invariants as checks on the status/policy responses — at most one pending owner, a loosening not before its timelock, freeze-unarmed-persists (C-R7-6), `NOT_ARMED` before an `Arm` on the pause build; `Envelope::unseal` and `recovery::decrypt` return `None` on every mutation of an honest blob. **No state-machine model** (RESP-r10). |

C-R10-1/2/3 remain in force on the new targets where a decoder or a signature is in the path (every structured
message is also fed re-encoded; every token/attest the same way).

## 2. Harness changes

- Five bodies in `src/targets.rs`, five `[[bin]]`s, seeds: the 54 vectors' `psbt_hex`/`state_hex`, the signet header
  vector, the rcore replay transcript (`enclave/rcore/tests/replay.rs` smoke sequence) for `dispatch`; dicts for op
  codes and PSBT key types; `run.sh` limits: `classify` `-max_len = MAX_PSBT`, `headers` 80 × 64 + a state, `state_ops`
  and `judge` 16 KiB, `dispatch` 64 KiB with `-malloc_limit_mb` below the proto bound.
- The F10 target needs `rcore` on the host: a path dependency on `enclave/rcore` with `features = ["nosgx",
  "test-init"]`. **Q1:** inside the `fuzz/` crate (one gate, rcore compiled host-side like `signerd`'s nosgx tests
  do) — the dev's pick — or a second crate `fuzz-rcore/` with its own gate?
- `coverage.sh` per new target (C-R10-7a): `state.rs` apply paths, `headers.rs`, `classify.rs`, `judge.rs`,
  `enclave/rcore/src/ops.rs`.
- `injected-defects.sh` gains at least one case per new oracle class (C-R10-7b): `classify` — the `non_witness_utxo`
  txid check dropped (I2); `judge` — a cap check dropped, and `disarm` made to fire on tip lag (C-R10-4 both
  directions: one case broadens, one narrows); `headers` — `add_work_le` made wrapping (C-R10-6); `state` — the
  `activation_height` wait dropped, and the F-01 frozen at-once branch disabled; `ops` — a `Stale` op writing the
  blob. Phase 2 is not claimed until every class has (a) and (b).
- The hollow guard for the targets themselves: each oracle's seed set includes the negative case it refuses
  (as in phase 1).

## 3. Order and passes

**Q2:** one impl REQ per pair, each with its own IMPL-PASS — (i) `state_ops` + `headers` (P0, core only, carries
C-R10-6 and the O01 invariant), (ii) `classify` + `judge` (P0, carries C-R10-4), (iii) `dispatch` (P1, rcore) — the
dev's pick, for three smaller reviews; or one impl REQ for all five?

**Q3:** the `disarms` set. The dev reads the code as exactly one site (`judge.rs:170–171`: a verified witness token
with `last_seen_seq > s.seq`); the C-R10-4 oracle will assert exactly that set. Confirm, or name the set you want
asserted.

**Q4:** F6's no-wrap input. The generator reaches the overflow by decoding a state whose `HeaderRec.work` is near
`2^256` — a value the enclave's own sealed blob could never hold, but the arithmetic is the oracle (RESP-r10 C6
"asserted explicitly"). Acceptable as the way to reach it, or do you want a unit-level oracle on `add_work_le` only?

## 4. Runs and evidence (as phase 1)

Shakeout 10 min per target, then one hour each on the laptop; corpus `cmin`'d; `coverage.sh` and
`injected-defects.sh` results in the impl REQ; findings through `findings/` with the auditor's ruling before any fix.
