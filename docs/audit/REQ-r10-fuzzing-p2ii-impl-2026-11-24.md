# REQ-r10 phase 2, pass (ii) — impl: `classify` (F7) and `judge` (F8)

**Date:** 2026-11-24. **Status:** SENT for IMPL-PASS against C-R10-4 (both directions), C-R10-7 (a)/(b) for the F7/F8
classes and the pass-(ii) rows of the phase 2 design (`REQ-r10-fuzzing-phase2-design-2026-11-21.md`, DESIGN-PASS; Q3's
`disarms` set confirmed = `judge.rs:170–171`). **Branch:** `r10-p2-classify-judge` (based on `main` `359991a`).
**Scope:** `fuzz/` only — `core/`, `enclave/`, `host/`, `owner/` untouched; no core visibility change was needed.

## 1. What landed

| Path | What |
|---|---|
| `fuzz/src/policy.rs` | the scripted PSBT generator over the vector fixtures (hot wallet `0x01`, cold `0x02`, a foreign wallet `0x77`; the honest mandate) with **one host-asserted lie on demand**; the harness's own ordered reading of the classifier's rules; the two bodies |
| `fuzz/fuzz_targets/{classify,judge}.rs`, `Cargo.toml` | the libFuzzer binaries |
| `fuzz/tests/replay.rs` | seeds (`classify_seeds` 48, `judge_seeds` 33) replayed by the gate and by `honest_objects_pass_their_targets`; `spend_spec` — the sane payout every seed starts from (own 2 000 000 in; unlisted 900 000 + own change 1 098 000 out; fee 2 000) |
| `fuzz/regressions/classify/REG-2026-11-24-harness-*` | six inputs that caught **harness** mistakes during the runs (§5), kept so the gate guards the corrected reading |
| `fuzz/corpus/{classify,judge}` | the grown corpora after `cmin` |
| `fuzz/injected-defects.sh` | six new cases (§5 b) |
| `fuzz/run.sh`, `.github/workflows/fuzz-smoke.yml`, `fuzz/README.md` | limits (`classify` 65536/64 — raw PSBTs; `judge` 256/16), the smoke list, the layout |

## 2. The generator, the lies, the knobs

A spec is `[n_in, n_out, version, flags, lie, target] ‖ n_in × [kind, index, lo, hi] ‖ n_out × [kind, index, lo, hi]`
(1–4 inputs and outputs; amount = 1000 + u16·1000 sat, with `0xffff` = `u64::MAX − 1000` and `0xfffe` = `u64::MAX/2 + 1`
for the overflow corner; `flags`: rbf, every input carrying `sighash_type = ALL` explicitly). Inputs: our key with its
hint, our key **without** a hint (the enclave must treat it as foreign), a foreign key. Outputs: ours (branch `idx % 2`,
index `idx / 2`), the trusted cold descriptor within its gap, the cold wallet **beyond** the gap (unlisted by the rules),
a foreign script, an `OP_RETURN`. The build is the vector suite's shape (a funding transaction per input,
`non_witness_utxo` set, bip32 hints), with exactly one of **fourteen** lies applied to the target input/output:

| # | Lie (what the host asserts) | Must draw |
|---|---|---|
| 1 | no previous transaction, a `witness_utxo` claiming three times the amount | `INPUT_NO_PREVTX` |
| 2 | a `witness_utxo` disagreeing with the previous transaction by one sat | `INPUT_PREVTX_MISMATCH` |
| 3 | a previous transaction with the same script and amount but another txid | `INPUT_PREVTX_MISMATCH` |
| 4 | our path in the hint, another index's key | `INPUT_NOT_OWN` |
| 5 | a foreign input dressed as ours (our key and path in the hint, a foreign script) | `INPUT_NOT_OWN` — on our own unhinted input the same bytes are a *correct* hint and the input becomes ours |
| 6 | an output hint with a foreign key under our path | `OUTPUT_SCRIPT_TYPE` |
| 7 | an own output rebuilt at index `gap + k` with a correct hint | `CHANGE_INDEX_BEYOND_GAP` |
| 8 | `sighash_type = NONE` | `SIGHASH` |
| 9 | the same outpoint twice | `PSBT_PARSE` |
| 10 | an unknown PSBT field on an input (type `0xf0`; `0xfc` is the proprietary type and does not parse) | `UNKNOWN_FIELD` |
| 11 | our key and path in the hint on **someone else's** output script | `OUTPUT_SCRIPT_TYPE` |
| 12 | an unknown PSBT field on an output | `UNKNOWN_FIELD` |
| 13 | our fingerprint and key at a **third branch** in an output hint | ignored (`own_path_from_origin` knows branches 0 and 1 only) — our own script without a verified hint is `Unlisted` |

Mandate knobs (`classify` mode 1, one byte): `OP_RETURN` rule `ZeroValue`; `max_inputs = max_outputs = 2`
(`TOO_MANY_INPUTS` / `TOO_MANY_OUTPUTS` before anything is read); no script type listed (`INPUT_SCRIPT_TYPE` for an own
input). A seed-only raw PSBT without outputs (`PSBT_PARSE`).

## 3. Targets and oracles as implemented

**`classify`** — mode 0: raw PSBT bytes; on `Ok(c)` the Ok-side invariants against the PSBT itself: every input has
its previous transaction whose txid is the outpoint's and whose output is the counted amount (I2), every `Own` input's
script is the one derived at its path (I1), every `Own` output's script is the derived one and its index is below
`bound + gap` (I3), an `OpReturn` has value 0, counts and `txid` match. Mode 1: the scripted build against the
harness's reading — one ordered walk (the counts against the mandate, the duplicate outpoint, then inputs in order,
then outputs in order; **the first refusal decides**) with the one lie's effect folded in at its target; a lie must
draw **exactly** its refusal (table above) unless the build's own earlier refusal wins (an `OP_RETURN` at output 0
under rule `None` before a lie at output 1); an honest build must be accepted with **exactly** the classes the reading
gives (our hinted inputs `Own` at their paths and amounts, unhinted and foreign `Foreign`, cold within the gap
`Trusted{dest 0}`, cold beyond the gap and foreign scripts `Unlisted`, `OpReturn` under `ZeroValue`), version, rbf,
txid. Mode 2, **the host never decides**: an honest build that classifies, then every lie on every target — each is
refused or accepted **only** as the honest classification, with exactly two allowed differences, both in the direction
of *less* being signed or recognised by the host's word and both verified by the enclave against derived keys and
scripts: a correct hint added to our own unhinted input makes it `Own` (and the vsize lower bound may only grow — a
p2wpkh input of ours carries a witness), and the one hint that made an output ours withheld (lie 13) makes it
`Unlisted`; the accepted lied build must also equal the reading and pass the Ok-side checks; an agreeing
`witness_utxo` changes nothing; an own input stripped of its hint is never ours.

**`judge`** — `[flags, witness, seq, fill, best_delta, payjoin, scale] ‖ spec` over the honest fixture state: flags set
the owner's freeze, unarmed, the chain freeze, an expired mandate, freshness required, rbf forbidden, a fee window
cap, `OP_RETURN` allowed; caps shrink by `2^(scale & 7)` (so the 1 BTC cold and outflow caps fall within the
generator's amounts and `CAP_TRUSTED_TX` / `CAP_TRUSTED_WINDOW` are reachable by construction); `scale & 8` sets
`max_fee_rate = u64::MAX` — *"a rate cap too large to multiply is no cap at all; `max_fee_abs` still binds"*; the
window is pre-filled by `fill/256` of each cap; `best` advances; the witness is none / fresh (`last_seen_seq ≤ seq`) /
**verified seq-behind** / unverified with a high seq (the AK signs it) / lagging tip / unknown tip hash / another
enclave's / a tip above best / **a `Cancel` message offered as the token**. The PSBT is the scripted honest build,
classified by the enclave first (a refusal there ends the case). Oracles: `judge` is a pure function of its inputs
(called twice); the **liveness refusals in the enclave's order** (`FROZEN`, `FRESHNESS_SEQ_BEHIND` for unarmed,
`CHAIN_REORG`, `MANDATE_EXPIRED`, `FRESHNESS_MISSING` / `_SIG` / `_TIP`), each with **no** disarm; **C-R10-4 both
directions**: `disarm.is_some()` **iff** the token is a `WitnessToken` that verifies under the mandate's witness key,
names this enclave, has a known tip within `max_tip_lag`, and `last_seen_seq > seq` — and the disarmed state is
unarmed; a wrapping sum ⇒ the single reason `OVERFLOW`; outputs above inputs ⇒ `PSBT_PARSE`; otherwise the **full
refusal set** recomputed by the harness from §1.4 (`TX_VERSION`, `RBF_FORBIDDEN`, `INPUT_FOREIGN_FORBIDDEN` for payjoin
`None` and for `InflowOnly` with a net outflow, `INPUT_NOT_OWN`, `CAP_TX`, `CAP_UNLISTED_TX`, `CAP_TRUSTED_TX`, `FEE_ABS`,
`FEE_RATE` over the enclave's own vsize lower bound, `CAP_WINDOW`, `CAP_UNLISTED_WINDOW`, `FEE_WINDOW`,
`CAP_TRUSTED_WINDOW`) must equal the enclave's as a multiset of codes, with no disarm; on `Accept` the set must be empty
and the charge exact — `window.outflow / unlisted / fees` and every trusted label increased by exactly the amounts,
`seq + 1`, the own-index bound raised to the highest own index + 1 over inputs and outputs, the summary's
amounts/txid/height, the mandate and the liveness flags untouched; judging the same transaction again from the
charged state never moves the window backwards.

## 4. The gate

`cargo test --no-default-features`: 3413 inputs over 15 targets (seeds, corpora, regressions); fmt and clippy
clean. The gate takes ~40 s on the laptop now — each `classify`/`judge` input derives keys and builds a PSBT,
and a mode-2 input runs about fifty classifications; CI's `fuzz-replay` job is correspondingly slower (watched).

## 5. Runs and C-R10-7

All runs on the laptop (`fuzz/run.sh`, libFuzzer fork mode, the pinned nightly), commit 2d90a54 for the final pair;
logs in the gitignored `.local/fuzz-runs/` (`shake-p2ii-*`, `hour-p2ii-*`, `hour-p2ii-*-final`):

| Run | Target | Workers | Wall time | Executions | oom/timeout/crash | Outcome |
|---|---|---|---|---|---|---|
| shakeout | `classify` | 2 | stopped at the first crash (twice) | — | 0/0/1 ×2 | two harness mistakes in the reading (1–2 below), fixed, kept as regressions |
| shakeout | `judge` | 2 | 611 s | 230 758 | 0/0/0 | clean |
| run 1 | `classify` | 4 | stopped at 17 s | — | 0/0/1 | the differential's harness mistake (3–6 below), fixed, four inputs kept as regressions |
| run 1 | `judge` | 4 | 3 624 s | 2 128 228 | 0/0/0 | clean; cov 3 358 |
| run 2 | `classify` | 4 | 740 s, killed | 268 359 | 0/0/0 | clean until killed (below) |
| run 2 | `judge` | 4 | 205 s, killed | 67 390 | 0/0/0 | clean until killed (below) |
| **final** | `classify` | 4 | **3 618 s** | **752 681** | **0/0/0** | **clean**; cov 4 307, ft 14 359; corpus 568 → 467 after `cmin` |
| **final** | `judge` | 4 | **3 625 s** | **1 517 817** | **0/0/0** | **clean**; cov 3 393, ft 8 837; corpus 177 → 171 after `cmin` |

No input in `findings/`: nothing the final harness found is a core finding. The `classify` target runs at ~50–100
exec/s per worker (every input derives keys and builds a PSBT; a mode-2 input runs ~50 classifications), `judge` at
~130–150: the hour is correspondingly fewer executions than the pass (i) decoders had, and the corpus — not the
execution count — is what the gate replays.

**Harness mistakes the runs caught (six, all in `classify`'s reading, each kept as a regression — none a core
finding):** (1) the reading named `OP_RETURN_FORBIDDEN` for an own change beyond the gap at output 0 followed by an
`OP_RETURN` at output 1 — the enclave walks outputs in order and names `CHANGE_INDEX_BEYOND_GAP` first (the reading
was rewritten as one ordered walk); (2) an output-script lie on an `OP_RETURN` output turns it into a foreign script
with our hint — `OUTPUT_SCRIPT_TYPE`, not an `OP_RETURN`; (3–6, the differential) a correct hint on our own unhinted
input legitimately makes it ours and raises the vsize lower bound by the p2wpkh witness — the differential's
"identical or refused" was too strict and now allows exactly that change. The reading is in `expected()`; the enclave
was right every time.

**(b) Injected defects — 21 cases, 21 caught, `core/` clean after each** (log
`.local/fuzz-runs/injected-defects-p2ii-final-2026-11-24.log`); the six new ones and what catches each:

| Reverted guard | Caught by |
|---|---|
| `classify`: the previous-tx txid check dropped (I2) | `classify` seed — the swapped previous tx (same script, same amount, another txid) is accepted ⇒ "ACCEPTED although the rules refuse (INPUT_PREVTX_MISMATCH)" |
| `classify`: the own-output script check dropped (I3) | seed — our key and path in the hint on someone else's script, accepted as `Own` |
| `classify`: the own-index gap check dropped (I3) | seed — the change at index 127 (gap 100) is accepted |
| `judge`: the per-transaction outflow cap dropped | `judge` seed — the refusal set lacks `CAP_TX` |
| `judge`: disarm broadened (`>=`) | the fresh token with `last_seen_seq == seq` disarms ⇒ "C-R10-4: a cap/structure refusal disarmed the signer" — the **not broader** direction |
| `judge`: disarm narrowed (`true` → `false`) | the verified seq-behind token no longer disarms ⇒ "disarm fired on the wrong refusal class" — the **not narrower** direction |

**(a) Reachability** (`fuzz/coverage.sh`, after the runs and `cmin`):

`classify` target (inputs: corpus 467 after `cmin`, 48 seeds, 6 regressions): `classify.rs` **93.23 %** of lines
(`classify_inner` 146/151, `classify` 10/10, `classify_psbt` 14/14, `varint_len` 4/7), 92.26 % of regions — up from
90.10 % after the first coverage pass (the two lies, the honest variation and the two mandate knobs were added for
exactly those lines). `judge` target (corpus 171 after `cmin`, 33 seeds): `judge.rs` **95.87 %** of lines
(`judge_checks` 183/187, `judge_inner` 19/19, `judge` 6/6, `add` 3/3), 95.27 % of regions; `classify.rs` under
`judge` 81.77 % (honest builds only, by design). Every unexecuted line of both files is in the table below, from
`llvm-cov show -show-line-counts-or-regions` on the final profiles; none is a policy decision an input could reach.

Lines of `classify.rs` / `judge.rs` the inputs do not execute, and why:

| Line(s) | What | Why not reached |
|---|---|---|
| `classify.rs` 106–108 | `varint_len` arms for ≥ 253 (the vsize bound's count encoding) | needs ≥ 253 inputs or outputs under a mandate allowing them; not generated (the bound's exactness is not an oracle of this pass) |
| `classify.rs` 191, 197 | `psbt.version != 0`, input/output count mismatch — structural guards | the `bitcoin` deserializer refuses both before `classify` sees them — defensive, kept |
| `classify.rs` 255 | the `witness_utxo`-only branch (`hollow-test` only: the I2 guard removed) | not compiled in the real build |
| `classify.rs` 278 | "own but not p2wpkh" — `INPUT_SCRIPT_TYPE`'s first arm | unreachable: an `Own` input's script was just matched to `p2wpkh_at(path)`; the second arm (type not listed) is reached by the knob |
| `classify.rs` 317 | `continue` on an own path at a branch > 1 in an output hint | defensive: `own_path_from_origin` already returns `None` for any branch but 0/1 (`wallet.rs:64`), so lie 13 takes the `None` path — the hint is ignored there, not here |
| `judge.rs` 270, 303, 320–321 | the closing braces of the implicit `else` of a trusted label not in the mandate (×2) and of `window_caps` | a `Trusted` class names a mandate destination by construction; `window_caps` is `true` outside `hollow-test` |

## 6. Deviations, stated

- The judge target feeds **honest** classifications only (the lies are `classify`'s business); the state is driven
  by the fixture helpers (`set_best`, the flags), as in pass (i).
- The harness's refusal model mirrors the enclave's **order** for the liveness checks (so the reason it names is the
  one the enclave names first) and treats the cap checks as a **set** — the design's "`Refuse` carries ≥ 1 reason" is
  strengthened to "exactly the set the rules give".
- `FEE_RATE` is checked against the enclave's own `vsize_lower_bound` (an output of `classify`, an input to `judge`);
  the bound's correctness is not an oracle of this pass.
- Raw-mode `classify` runs with `-max_len` 64 KiB, below the proto bound of 256 KiB, to keep the fuzzer fast; the
  bound itself is `proto_decode`'s business.
- The `classify` reading's order for the lies is the enclave's order of checks (structure → inputs → outputs); the
  *values* — which field decides, what must be refused — come from the design's I1–I4 and `POLICY.md`.
- Run 2 was not a fuzzing result: both workers' processes were killed by the session tool for low system memory on
  the laptop (two unrelated Java processes held ~6.4 GB of 15 GB); the eight `timeout-*` artefacts left behind were
  kill artefacts (each replays in 57–215 ms, the crash counters at 0/0/0 in both logs) and were deleted by their
  enumerated paths, not kept as findings. The runs were repeated in full once memory was free (the **final** row).

## 7. For the auditor's run

```bash
cd fuzz && cargo test --no-default-features                       # the gate, 15 targets
./injected-defects.sh                                             # 21/21, core/ clean after
./run.sh classify 60 1; ./run.sh judge 60 1                       # nightly
./coverage.sh classify; ./coverage.sh judge                       # per-function reach of classify.rs / judge.rs
```
