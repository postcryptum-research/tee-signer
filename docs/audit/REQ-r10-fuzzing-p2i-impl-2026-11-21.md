# REQ-r10 phase 2, pass (i) — impl: `state_ops` (F4), `headers` (F6), `work_add` (C-R10P2-2)

**Date:** 2026-11-21. **Status:** **IMPL-PASS (scoped)** at `14e1965` → `RESP-r10-fuzzing-p2i-impl-2026-11-21.md` (same day; the production footprint — `add_work_le` made `pub` — and the finding verified firsthand, the harness accounting credited; closes on the PR's CI conclusion; the PR is harness-only against the real `main`, see the RESP header). F-2026-11-21-01 ruled a **DEFECT** (fix authorized, next core round) and the `timelock_blocks` cap supported — both in `REQ-r10-f02-owner-at-activation-timelock-cap-2026-11-21.md`. Sent for IMPL-PASS against C-R10-6, C-R10-7 (a)/(b) for the F4/F6 classes,
C-R10P2-1, C-R10P2-2, C-R10-F (design: `REQ-r10-fuzzing-phase2-design-2026-11-21.md`, DESIGN-PASS; sequencing per
RESP: after O01 landed on `main` at `97d3684`). **Branch:** `r10-p2-state-headers` (based on `main` after PR #3).
**Scope:** `fuzz/` only — `core/`, `enclave/`, `host/`, `owner/` untouched (`git diff --stat main...HEAD -- core
enclave host owner` empty); the one `core/` line the design named (`add_work_le` made `pub`) rode O01.

## 1. What landed

| Path | What |
|---|---|
| `fuzz/src/gen.rs` | the generators: a regtest miner on the fixture checkpoint (`mine`, `raw`, `hash32`, `regtest_state(max_reorg)`), `work_of_bits`, the **reference** 256-bit LE adder `add256_ref` (written independently of `headers::add_work_le`) and `le_cmp` |
| `fuzz/src/structured.rs` | the three bodies; inputs are **scripted** fixed-size records, not `arbitrary`-driven — every seed is hand-writable and every injected defect has a deterministic reproducer (a deviation from the design's "`arbitrary`-driven", stated in §6) |
| `fuzz/fuzz_targets/{work_add,headers,state_ops}.rs`, `Cargo.toml` | the libFuzzer binaries |
| `fuzz/tests/replay.rs` | seeds (`work_add_seeds` 7, `headers_seeds` 19, `state_ops_seeds` 49) replayed by the gate and by `honest_objects_pass_their_targets`; the seed writer |
| `fuzz/regressions/state_ops/` | two reproducers of the harness's own false positives (§4), kept — they must pass |
| `fuzz/findings/state_ops/` | **open** finding F-2026-11-21-01 (§5a): reproducer + `FINDING.md`; the gate asserts it still fires |
| `fuzz/injected-defects.sh` | five new cases (§5) |
| `fuzz/run.sh`, `.github/workflows/fuzz-smoke.yml`, `fuzz/README.md` | limits (`headers` 8192/64, `state_ops` 256/16, `work_add` 64/16), the smoke list, the layout |

## 2. Targets and oracles as implemented

**`work_add`** — 64 bytes = two LE 256-bit operands. `add_work_le(a,b) == add_work_le(b,a)`; `None` **iff** the
reference sum carries out of 2^256; `Some(s)` ⇒ `s` equals the reference sum and is not below either operand.
Seeds straddle the boundary deterministically: `2^256−1 + 1` and `2^255 + 2^255` (→ `None`), `2^255−1 + 2^255`
(→ `Some(2^256−1)`), zeros, two regtest header works.

**`headers`** — `mode ‖ max_reorg ‖ …` over the regtest fixture (checkpoint at height 100, `max_reorg` 1–8) or the
signet fixture (checkpoint = the vector's header 322 560, a retarget boundary):
- mode 0, raw: up to 64 raw headers in one batch, applied twice. Invariants after every call (`chain_invariants`):
  `best.work` never decreases; `recent` contiguous, ends at `best`, strictly increasing work, `len ≤ max_reorg +
  RECENT_EXTRA` and `≤ MAX_RECENT`; `CHAIN_REORG` ⇒ `frozen`; any other `Err` ⇒ the chain view unchanged; `Ok(0)` ⇒
  `best` unchanged; a frozen chain refuses every batch with `CHAIN_REORG` and never changes; an undecodable header
  ⇒ `Err` and the state unchanged.
- mode 1, scripted: records `[op, d, k]` (≤ 12) — extend by `k`, fork at depth `d` with `k` blocks, extend by `k`
  delivered as two batches split at `d` — against a **model chain** the harness mines itself. Exact expectations:
  extend ⇒ `Ok(k)`; fork: `d ≥ |recent|` ⇒ `HEADER_INVALID` (the attach point left `recent`), `d > max_reorg` ⇒
  `CHAIN_REORG` and frozen from then on, `k > d` ⇒ adopted `Ok(k)`, `k ≤ d` ⇒ `Ok(0)` (equal work is not more
  work); after every step `best.height/hash` and `frozen` equal the model's.
- mode 2, signet: the first `n ≤ 64` real headers with one byte XORed at an arbitrary position (or none): the
  invariants above, growth ≤ `n`.
- mode 3, the boundary at the call site: the fixture's `best.work`/`recent[].work` set to the 32 input bytes,
  then one mined header: `OVERFLOW` and the state unchanged **iff** the reference sum reaches 2^256, else `Ok(1)`
  with `best.work` equal to the reference sum (C-R10-6 where `apply_headers` adds);
- mode 4, the real signet chain **across its retarget boundary** (2016 + n headers after the checkpoint, two batches
  split at an arbitrary point, optional one-byte mutation in the tail): the untouched chain must be accepted whole
  and end at the right height; the invariants above on every batch;
- mode 5, regtest mined past the height-2016 boundary, then a fork attaching in the **previous** retarget period:
  adopted / equal work / `CHAIN_REORG` exactly per the mode-1 rules, the adopted fork's tip is `best`.

**`state_ops`** — 8-byte step records (≤ 24) over the honest fixture state (the vectors' keys and mandate, best
250 010): kinds 0–8 are `PolicyUpdate` (a structured mutation of the installed mandate via `mutate_mandate`, or:
identical, a re-pin to a verified recent header, a frozen-style checkpoint-only re-pin, a deterministic loosening;
flags for a stranger's signature and a wrong nonce), `Cancel` (owner or recovery), `Unfreeze`, `Rearm`,
`RotateOwner` / `Recover` (targets: the witness key, the AK key, a non-point, the recovery key), `Arm` and `Anchor`
through `apply_arm`/`apply_anchor` (this load's challenge or another's, `seq_seen`, counter vs live counter), and
`WitnessToken` (C-R10P2-1: the ninth arm, always `POLICY_INVALID`, nonce intact); kinds 9–11 drive the chain through
the fixture helpers — advance `best`, freeze the chain (a deep reorg), the owner's freeze. The signing key follows
the owner: after `Recover` or an activated rotation the harness signs with the new owner key (the witness or AK
key, both held). Oracles:
- the exact refusal for a stranger's signature (`POLICY_SIG`), a wrong nonce (`POLICY_NONCE`), a second update while
  one is pending (`POLICY_PENDING`), a rotation while one is pending, a non-point or the recovery key as the new
  owner (`POLICY_INVALID`), another load's challenge (`ARM_CHALLENGE`), a `seq_seen` the enclave never reached
  (`ARM_SEQ_BEHIND`), a certified counter behind the live one (`ANCHOR_COUNTER_BEHIND`), a witness token through
  `apply_message` (`POLICY_INVALID`);
- `PolicyUpdate` by the owner: the outcome the REQ-r10-F01 / REQ-r10-O01 tables prescribe, computed by the
  harness's own `expected_update` (validity → network → wallet → **frozen ∧ checkpoint unchanged ⇒
  `CHAIN_REORG`** → checkpoint changed: frozen ⇒ checkpoint-only ⇒ at once, else `POLICY_INVALID`; unfrozen ⇒
  pinned by the enclave's own record (hash/height/time/bits, period fields within the current retarget period) else
  `POLICY_INVALID` → `compare`: `Tightening` ⇒ installed now and the chain view kept, `Loosening` ⇒ pending with
  `activation_height = best + timelock_blocks` and the installed mandate unchanged);
- the **harness's own timelock model** (`state_invariants`): a pending mandate or owner is due iff `best ≥
  activation_height`; on any accepted operation a due pending activates (and is the installed one unless the
  operation clears — `Cancel`, `Recover`), a not-yet-due pending is unchanged and the installed mandate / owner key
  did not move; `nonce` moves by exactly one per accepted owner message and not at all on a refusal; the installed
  mandate validates after every step; the live state round-trips (`State::decode(encode(s)) == s`, C-R10-2);
- `Cancel` clears both pendings; `Unfreeze` clears the owner's freeze; `Rearm` arms and never lowers `seq`;
  `RotateOwner` queues the new owner at `best + timelock` and does not change the owner; `Recover` installs the new
  owner and voids everything in flight; `Arm`/`Anchor` leave the owner's freeze and the sealed `armed` flag alone
  (C-R7-6, the shell's volatile fact) and `Anchor` pins `TpmAnchor { ak, nv_name, expected: live }`;
- a frozen checkpoint-only re-pin clears the freeze, restarts the chain from it and installs at once (C-F01-1);
  every other update while frozen is refused `CHAIN_REORG` (O01) — both halves.

## 3. The gate

`cargo test --no-default-features` in `fuzz/`: **2719 inputs over 13 targets** (375 seeds, 2339 corpus files, 4
regressions, 1 open-finding reproducer asserted to still fire), ~18 s on the laptop once built — the new targets mine regtest headers at replay
(mode 5 mines ~1 920 per input), which is where the time went from 4 s; acceptable, watched. `honest_objects_pass_their_targets`
runs every new seed as well. fmt and clippy `-D warnings` clean.

## 4. Runs (laptop)

Laptop only. Shakeout 10 min with two workers, then one hour with one worker each, all three in parallel
(2026-11-21). No timeout, no OOM, no `-malloc_limit_mb` hit; libFuzzer's slowest unit 0 s; peak RSS 425–466 MB.

| Target | Shakeout | 1 h run: executions, `cov` | Corpus after `cmin` | Crashes |
|---|---|---|---|---|
| `work_add` | clean | 232.3 M, 317 | 58 → 58 | 0 |
| `headers` | clean | 231 k, 1889 | 539 → 147 | 0 |
| `state_ops` | 1 crash — the **harness's** false positive, see below | 15.8 k, 2237 | 307 → 226 | 1 — the harness's second false positive, see below |

Both `state_ops` crashes were the harness model, not the enclave — kept as regressions (they must pass now):
- `REG-2026-11-21-02-harness-due-pending-then-update`: a loosening, +161 blocks (due), then an update. The enclave
  activates the due pending first and then installs the new tightening; the harness demanded the activated pending
  to be the installed one. Fixed by making the timelock model effect-aware (`Plain` / `Clears` / `Installs` /
  `Queues` / `QueuesOwner`): a due pending always activates; what may replace, re-queue or clear afterwards is
  the operation's own effect.
- `REG-2026-11-21-03-harness-timelock-overflow`: a tightening that raises `timelock_blocks` near `u32::MAX`, then a
  loosening. The enclave refuses `OVERFLOW` (`best.checked_add(timelock)`), the harness expected a pending at a
  saturated height. Fixed: the model refuses `OVERFLOW` exactly when `best + timelock` does not fit — and the same
  for a rotation. **Observation for the auditor (not a defect, named):** an owner who installs a timelock larger
  than the remaining height space makes every later loosening and rotation unqueueable until a tightening lowers
  it; `validate` could cap `timelock_blocks` (e.g. ≤ 52 560 ≈ one year) — a design question for the next core round,
  not this pass.

A third harness gap was found by coverage, not by a crash: the signet modes had fed the vector's header 0 — the
fixture's own checkpoint — as the first header, so every signet batch was silently refused `HEADER_INVALID` and the
invariants held vacuously. Fixed (the chain to feed starts after the checkpoint) and the clean real chain is now
**asserted accepted**, across the retarget boundary in mode 4 — which is why mode 4/5 exist: the first coverage
report showed the retarget bookkeeping unreached. Post-fix shakeout of `headers` and `state_ops` (10 min, two workers): `headers` clean (`cov` 1889 → 2012 with
the signet modes now really applied; corpus 147 → 165 → 154 after `cmin`); `state_ops` **one crash — a real one
this time, F-2026-11-21-01 (§5a)**; corpus 226 → 238 → 217.

## 5a. Finding — the path exercised again

### F-2026-11-21-01 — `apply_arm` / `apply_anchor` verify against the owner **before** a due rotation activates — **OPEN, for the auditor's ruling**

Found within ten minutes of the post-fix shakeout. `RotateOwner` to the witness key, the chain advanced past the
activation height, then an `Anchor` signed by the new owner ⇒ `POLICY_SIG`. Every `apply_message` arm verifies
against the owner **after** `activate_pending` (`state.rs:401–408`); `apply_arm` (`:557`) and `apply_anchor`
(`:611`) verify `self.owner_pk` first and activate three lines later. Effect: at the rotation boundary the new
owner's `Arm`/`Anchor` is refused until any other owner message activates the rotation (liveness nit), and the old
owner key signs one more accepted `Arm` or `Anchor` — operations within the installed mandate, not a signing-boundary
change. Full entry: `fuzz/findings/state_ops/FINDING.md`; the reproducer is asserted to still fire by the gate; the
`fuzz-smoke` job runs `state_ops` past it, advisory, until it is resolved. Proposed fix (two lines moved in each of
the two functions) in the entry — not written (hard rule 1). **Question:** rule it (defect / accepted inconsistency /
spec wording), and whether its fix should ride the next core round together with the `timelock_blocks` cap question
of §4.

## 5. C-R10-7 for the F4/F6 classes

**(b) Injected defects — `fuzz/injected-defects.sh`, 15 cases, 15/15 caught, `core/` clean after each** (log
`.local/fuzz-runs/injected-defects-p2i-2026-11-21.log`); the five new ones and the seed that catches each:

| Reverted guard | Caught by |
|---|---|
| `add_work_le`: the carry-out check dropped (wrapping) | `work_add` seed 0 (`2^256−1 + 1`): "WRAPPED — a + b ≥ 2^256 yet Some" |
| `apply_headers`: the deep-reorg freeze dropped | `headers` seed 2 (scripted: fork at depth 5 > `max_reorg` 4 expected `CHAIN_REORG`) |
| `activate_pending`: the timelock wait dropped (both pendings activate at once) | `state_ops` seed 2 (a loosening, +1 block, an accepted op: "the installed mandate changed while a loosening was pending and not yet due") |
| the O01 refusal dropped | `state_ops` seed 12 (frozen, identical update: expected `CHAIN_REORG`) |
| the frozen at-once re-pin disabled (C-F01-1) | `state_ops` seed 13 (frozen checkpoint-only re-pin: expected to apply) |

**(a) Reachability** (`fuzz/coverage.sh`):

`fuzz/coverage.sh` per target after the one-hour runs, `cmin` and the final seeds (functions the targets are for,
lines executed/total):

| Target | Reached | Not executed, read |
|---|---|---|
| `work_add` | `add_work_le` 100 % (the only function it is for) | — |
| `headers` | `apply_headers` **83/84**, `required_bits`, `median_time`, `add_work_le`; `headers.rs` 89 % lines | `apply_headers`: `target > max_attainable_target ⇒ HEADER_INVALID` — unreachable while `bits == required_bits` holds and `required ≤ limit` on every network (defence in depth, kept); `headers.rs`: the mainnet and testnet4 `Params` arms (no fixture: mainnet by hard rule 3, testnet4 proof-of-work infeasible to mine in a fuzzer), the testnet4 min-difficulty branch of `required_bits` (same), `median_time`'s empty-chain `return 0` (`recent` is never empty) |
| `state_ops` | `apply_message` **118/120**, `apply_arm` **21/21**, `apply_anchor` **30/30**, `activate_pending`, `checkpoint_pinned`, `anchor_identity`, `compare` 48/54, `ChainState::from_checkpoint`; `state.rs` 89 % lines, `mandate.rs` 84 % | `apply_message`: the two `compare` `Immutable` arms — unreachable, the network and wallet are checked equal just before (defence in depth); `anchor_identity`'s non-`Anchor` arm — unreachable through `apply_anchor`, which matched the variant first; `compare`'s cross-mandate arms the mutations did not hit are `mandate_compare`'s (phase 1) |

Whole-crate line coverage: `work_add` 0.5 %, `headers` 17.5 %, `state_ops` 42.8 % — `judge.rs`/`classify.rs` are pass
(ii), `rcore` is pass (iii).

## 6. Deviations from the design, stated

- **Scripted records instead of `arbitrary`-driven generators.** Fixed-size step records read byte by byte give the
  same search space to libFuzzer and make every seed hand-writable and every injected defect deterministically
  reproducible (the design's own requirement for (b)); `arbitrary::Unstructured` is still used inside a step to
  drive `mutate_mandate`.
- **`state_ops` drives the chain through the fixture helpers** (`set_best`, the frozen flags), not through
  `apply_headers`: the header path is `headers`' job, and the synthetic chain of the vector fixture is not a real
  header chain. The frozen re-pin and the pinned re-pin are exercised against that synthetic `recent`.
- **`headers` mode 2 (signet) asserts the invariants, not an exact model**: the real chain's retarget/MTP rules
  are the vector test's, and the mutation's effect depends on the byte; the exact model lives in mode 1 (regtest).
- Seeds for the signet mode read `vectors/headers/signet-322560-324700.hex` at run time (first 64 headers).

## 7. For the auditor's run

```bash
cd fuzz && cargo test --no-default-features                       # the gate, 13 targets
./injected-defects.sh                                             # 15/15, core/ clean after
./run.sh state_ops 60 1; ./run.sh headers 60 1; ./run.sh work_add 60 1   # nightly
./coverage.sh state_ops; ./coverage.sh headers                    # per-function reach of state.rs / headers.rs
```
