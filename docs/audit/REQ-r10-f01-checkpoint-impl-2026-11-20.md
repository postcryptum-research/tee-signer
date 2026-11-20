# REQ-r10-F01 — the checkpoint in `compare` and at install: fix of fuzz finding F-2026-11-20-01 (impl REQ)

**Date:** 2026-11-20 (drafted), 2026-11-21 (sent; implementation sent for IMPL-PASS the same day). **Status:** **IMPL-PASS (clean) at `10f6770`** — the auditor re-ran his own boundary-gate mutation and vector 15
reddened it (`RESP-r10-f01-checkpoint-impl-2026-11-21.md`, second part); merged to `main` via PR #2. Deploy consequence §5:
the rebuild (ENFORCE=1, the auditor's decorrelated build as the deploy-content gate), the ceremony signing and the
deploy are the owner's; the auditor reproduces the new MRENCLAVE when the build is cut. Before: IMPL-PASS CONDITIONAL at `6e05716` →
`RESP-r10-f01-checkpoint-impl-2026-11-21.md` (same day; legs 1–3 and the brick fix verified firsthand, the reproducers
retired); the one condition — a vector that only the current-period boundary gate refuses, and its hollow mutation —
**discharged on the branch** (§4 vector 15, §7: `scripts/hollow-f01.sh` 7/7), sent back for the clean pass. Branch
`r10-f01-checkpoint`, PR #2; merge only on the clean pass. §7 has what was run. Design: **DESIGN-PASS (CONDITIONAL)** at `3473e41` →
`RESP-r10-f01-checkpoint-design-2026-11-21.md` (same day): the unfrozen legs approved as drafted; the frozen path
**re-ruled** — a frozen re-pin applies at once (both forward and same-height), never through the timelock (§2a);
Q1 answered that way, Q2 = `Result`, Q3 = spell it out; conditions `C-F01-1 … C-F01-6` in `CONDITIONS.md`.
Implementation on branch `r10-f01-checkpoint`, IMPL-PASS before merge. Sent originally as the next, separate pass after
the harness's IMPL-PASS (`RESP-r10-fuzzing-impl-2026-11-20.md` at `9e2d2fc`; the auditor: "not folded into this one — it changes
`core/` and re-grades on its own merits"; he rules Q1 and Q2 in this pass). The finding went public first
(`fuzz/findings/`, `9e2d2fc`), then this fix. **No `core/` code is written before this REQ's DESIGN-PASS** (hard
rule 1: Q1 and Q2 shape the code); then implementation on branch `r10-f01-checkpoint`, no merge without IMPL-PASS,
a new MRENCLAVE with the next ceremony build, nothing deploys without the owner's GO.
**Finding:** `fuzz/findings/mandate_compare/FINDING.md` (F-2026-11-20-01; C-R10-5 fired after 82 executions).
**Ruling (auditor, 2026-11-20):** DEFECT, two legs, severity medium; plus the constructor-side invariant from the
reflexivity observation. The oracle is not weakened.
**Scope:** `core/src/mandate.rs` (`compare`, one expression), `core/src/state.rs` (`apply_message`, the
`PolicyUpdate` arm's checkpoint acceptance; `State::new_at_init`), vectors and tests; `POLICY.md §5` wording
if the auditor wants the rule spelled out; `rcore::ops::init` only if `new_at_init` changes signature. The host
and the owner tooling are unchanged.

## 1. Leg 1 — `compare`: the checkpoint rule (the unfrozen path; a frozen re-pin never reaches `compare`, §2a)

Today: `clear(new.checkpoint.height >= installed.checkpoint.height)` — a checkpoint with the same height and
different content (hash, time, bits, period fields) passes as "forward", so a content-only change is
`Tightening` in both directions and applies at once, without the installed mandate's timelock.

Change (approved by the auditor):

```rust
// checkpoint: unchanged, or moved strictly forward (POLICY.md §5). Same height with different content is
// neither — it fails toward loosening like every field that is not provably tightening (auditor R6).
clear(new.checkpoint == installed.checkpoint || new.checkpoint.height > installed.checkpoint.height);
```

Properties restored: identical ⇒ tightening (no-op); strictly forward ⇒ tightening; same height, different
content ⇒ loosening; backward ⇒ loosening. Antisymmetry holds (two distinct same-height mandates both loosen).

## 2. Leg 2 — install: a changed checkpoint is validated against the enclave's own chain, fail-closed

Today (`apply_message`, `PolicyUpdate`): a new checkpoint different from the installed one is accepted when
some `chain.recent` record matches its **hash and height**, or unconditionally while the chain is frozen
(re-pin). Its `time`, `bits`, `period_start_time`, `period_bits` are not compared with anything. A real hash
with attacker-chosen parameters is an internally inconsistent forgery that install accepts; those parameters
reach the chain view through `ChainState::from_checkpoint` on the frozen paths (re-pin; `activate_pending`).

Change — the rule is *validate or refuse, never document-and-trust*: on the unfrozen path a changed checkpoint
is accepted only if **every** field is pinned by the enclave's own state, else `PolicyInvalid`:

| Field | Pinned against | Not pinnable ⇒ |
|---|---|---|
| `hash`, `height` | a record `r` in `chain.recent` with both equal (as today), `height <= best` | `PolicyInvalid` (as today) |
| `time` | `r.time` | `PolicyInvalid` |
| `bits` | `r.bits` | `PolicyInvalid` |
| `period_start_time` | `chain.period_start_time`, **provided `r` lies in the current retarget period** (`r.height >= best.height - best.height % 2016`) | `PolicyInvalid` — a header of a previous period is not re-pinnable while unfrozen (the enclave keeps only `prev_period_start_time`, and the previous period's bits are not kept exactly: `apply_headers` itself notes that `fork_point.bits` is "exact on mainnet/signet" only — on testnet4 a min-difficulty header carries `powLimit`, not the period's bits) |
| `period_bits` | `chain.period_bits`, same current-period condition | `PolicyInvalid` |

Per network, what this pins: on every network the current period's `period_start_time`/`period_bits` are the
values `apply_headers` maintains, so they are exact for any `r` in the current period, including testnet4
(the period's bits are the first block's bits, which the enclave recorded; a min-difficulty `r` carries other
bits, and the checkpoint's `bits` is compared with `r.bits`, not with `period_bits`). Regtest:
`no_pow_retargeting` — the same comparisons hold trivially. Liveness cost: a legitimate re-pin to a header of
the previous period is refused while unfrozen; the owner picks a header of the current period (any header
since the last retarget boundary) or waits one block after a boundary. Boundary-aligned checkpoints
(`period_start_time == time`, `period_bits == bits`) pass by construction.

### 2a. The frozen path — re-ruled by the auditor: a re-pin applies at once, or the signer is bricked

As drafted (the timelock as the frozen path's control) the fix would have **permanently bricked** a frozen signer,
the auditor showed firsthand: the timelock is block-height anchored (`activation_height = best + timelock_blocks`,
`activate_pending` fires only when `best >= activation_height`), `apply_headers` refuses every header while the
chain is frozen, and `chain.best` is written only by `apply_headers` — so while frozen `best` is pinned and a
re-pin routed to `pending` never activates, the chain is never reset, the freeze is never cleared. Leg 1 as
drafted already did that to the same-height re-pin (a reorg deeper than `max_reorg` landing at the same tip
height is a real recovery case: leg 1 makes it `Loosening`, the old `repin` branch reset the chain only for
`Tightening`).

**Ruling (C-F01-1):** while the chain is frozen, a `PolicyUpdate` whose checkpoint differs from the installed one
is a re-pin and applies **at once** — forward or same-height — handled *before* `compare`: the chain is reset from
the new checkpoint, the mandate installed, the owner's signature stored; no timelock, because the block-height
timelock cannot run while frozen. The compare/timelock machinery is for unfrozen updates.

**Hardening taken (C-F01-2, the auditor's recommendation):** a frozen re-pin is **checkpoint-only** — it is refused
(`PolicyInvalid`) when the new mandate differs from the installed one in any field but the checkpoint. Recovery
needs the new trust root and nothing else; the frozen path does not double as a destination/limit-change path, so
a stolen owner key cannot swap destinations in one atomic frozen step.

**Residual, labelled (C-F01-5, `THREAT-MODEL.md`):** on the frozen path there is no local reference to validate
the checkpoint against — the deep reorg invalidated the local view — so leg 2 cannot apply there and nothing can
replace it; the owner signature is the irreducible root of trust for recovery. Precondition for abuse: V5 (stolen
owner key) **∧** a reorg deeper than `max_reorg` (≈ 51 % of mainnet hashpower; the signet key on signet; feasible on
testnet4). Named, not denied.

The unchanged branch of `activate_pending` (a pending mandate with a changed checkpoint activating while frozen
resets the chain from it) stays: that checkpoint passed leg 2 on the unfrozen path when it was queued.

## 3. The constructor invariant — `State::new_at_init`

`compare` matches trusted entries by the first entry with a label; on a mandate with duplicated labels it is
not reflexive (fuzz regressions `REG-2026-11-20-01-invalid-dup-labels-{a,b}`). Unreachable today: both write
sites validate first (`rcore::ops::init` before `new_at_init`; `apply_message` before `compare` and before
`s.mandate = new`). The auditor requires the invariant "the installed mandate is always validated" to be
enforced at the write site, not by caller discipline: `new_at_init` must not store an invalid mandate.

Ruled (Q2, C-F01-3): `new_at_init` returns `Result<State, Invalid>` and runs `mandate.validate()?` itself —
fail-closed in release too (`debug_assert!` is a no-op in release: a silent footgun). The only in-enclave caller,
`rcore::ops::init`, already refuses `PolicyInvalid`; the test callers (`core/tests/common::init_state`,
`core/tests/headers.rs`) unwrap.

## 4. Vectors and tests (the auditor's break-tests, both directions)

`core/tests/transitions.rs` (compare) and a new install vector set:

1. identical mandate re-installed ⇒ `Tightening`;
2. checkpoint strictly forward (a known recent header, all fields from the enclave's own record) ⇒
   `Tightening`, applies at once;
3. same height, different `hash` / `time` / `bits` / `period_start_time` / `period_bits` (five vectors) ⇒
   `Loosening` — and at install, since the content is not the known record's ⇒ `PolicyInvalid` (leg 2 fires
   before `compare` matters);
4. real hash + wrong `bits` ⇒ `PolicyInvalid`;
5. real hash + wrong `period_start_time`, `r` in the current period ⇒ `PolicyInvalid`;
6. real hash, `r` in the previous period (un-derivable period fields) ⇒ `PolicyInvalid` (fail-closed, not
   accepted);
7. positive: a genuine boundary-aligned checkpoint (`period_start_time == time`, `period_bits == bits`, `r` the
   first block of the current period) ⇒ accepted;
8. positive: a genuine mid-period checkpoint with the enclave's own period values ⇒ accepted;
9. the four F-01 reproducers move `fuzz/findings/` → `fuzz/regressions/` and pass C-R10-5 in both directions;
10. `new_at_init` with an invalid mandate ⇒ refused (`Result`, Q2);
11. hollow-test (C-R12b style): with the leg-2 field checks removed, vector 4 goes green — proven red/green;
12. **brick regression (auditor):** chain frozen, a SAME-HEIGHT, different-content re-pin ⇒ applies at once, the
    chain is reset from it and the freeze is cleared — this catches both the option-(ii) brick and leg 1 without
    the frozen carve-out;
13. chain frozen, a FORWARD re-pin ⇒ applies at once, chain reset;
14. chain frozen, a re-pin that also changes a non-checkpoint field ⇒ refused (`PolicyInvalid`, C-F01-2);
15. **(the auditor's condition, RESP impl)** a real previous-period header, every field as recorded, stamped with the
    CURRENT period's `period_start_time`/`period_bits` ⇒ `PolicyInvalid` — the forgery that passes every equality
    check and that only the current-period boundary gate refuses; with the gate alone removed this vector is the
    one that goes red.

`fuzz/injected-defects.sh` gains the case "leg-2 `bits` check dropped ⇒ caught by the install vector" once the
install path has a fuzz target (phase 2, F4 structured).

## 4a. What the branch does, file by file

| Path | Change |
|---|---|
| `core/src/mandate.rs` | `compare`: the checkpoint line (leg 1), with the F-01 reference; nothing else |
| `core/src/state.rs` | `apply_message`, `PolicyUpdate` arm: a changed checkpoint while **frozen** is handled first — checkpoint-only check (`new` with the installed checkpoint must equal the installed mandate, else `POLICY_INVALID`), then `chain = from_checkpoint(new)`, install, return (C-F01-1/2); while **unfrozen** `checkpoint_pinned(&chain, &new.checkpoint, best)` (leg 2, new private fn at the end of the file: hash/height a recent record `r` ≤ best, time/bits `r`'s, period fields the chain's and `r` in the current retarget period, else `POLICY_INVALID`); the old `repin` flag and its post-`compare` reset are gone; `new_at_init` → `Result<State, Invalid>`, `mandate.validate()?` first (C-F01-3); `activate_pending` unchanged |
| `enclave/rcore/src/ops.rs` | `init`: `let Ok(state) = State::new_at_init(…) else { refuse(POLICY_INVALID) }` |
| `core/tests/transitions.rs` | five same-height compare rows; the compare table now also asserts the reverse direction is `Loosening` for every tightening row (C-R10-5 in both directions on the vectors themselves); `update_refusals`' known-header case carries every pinned field; new `checkpoint_install_validates_every_field_fail_closed` (vectors 3–8: wrong time / bits / period start / period bits / hash, the installed height with other content, mid-period positive, the retarget boundary — previous-period header refused with every field matching the record, boundary-aligned positive, mid-period positive), new `frozen_repin_applies_at_once_and_is_checkpoint_only` (vectors 12–14 + four non-checkpoint changes each refused + an ordinary update while frozen with the checkpoint unchanged leaves the chain frozen), new `new_at_init_refuses_an_invalid_mandate` (vector 10) |
| `core/tests/common/mod.rs`, `core/tests/headers.rs` | the three `new_at_init` callers unwrap |
| `docs/POLICY.md` | `chain` section and the §5 `chain.checkpoint` row spelled out (C-F01-4) |
| `docs/THREAT-MODEL.md` | V5: the residual V5 ∧ frozen, bounded and named (C-F01-5) |
| `fuzz/regressions/mandate_compare/` | the four F-01 reproducers, moved from `findings/` (`FINDING.md` entry kept, marked RESOLVED with the RESP reference); the gate asserts they pass C-R10-5 both ways |
| `fuzz/injected-defects.sh` | tenth case: the pre-fix compare line brought back is caught by those reproducers |
| `fuzz/corpus/mandate_compare/` | re-grown and `cmin`'d on the branch (the fuzzer now explores past the checkpoint mutations) |

Not touched: the host, the owner tooling, the enclave shell, the wire format (no encoding change; `State::encode` and
the vectors' `state_hex` are byte-identical). `core/Cargo.lock`, `core/PROVENANCE.md` unchanged. **MRENCLAVE changes**
(§5).

## 5. Build and deployment consequence

`signer-core` changes ⇒ MRENCLAVE changes. Reproducible build on the box in Docker (`REPRODUCIBLE-BUILD.md`),
the auditor's decorrelated build as the deploy-content gate, ceremony signing by the owner, T2 migration by the
owner's script — the R9a procedure. Until then `main` carries the fix with the label "not yet the deployed
measurement" in `deploy/README.md`, and the deployed `2073c234…` is documented as carrying F-01 (severity medium,
chain-view impact gated on a frozen chain).

## 7. What was run (laptop, 2026-11-21)

- `cd core && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` — green (transitions: 10
  tests incl. the three new; vectors, headers, judge, unit tests unchanged and green: the fix changes no wire byte).
- `cd enclave/rcore && cargo fmt --check && cargo clippy --features nosgx,test-init --all-targets -- -D warnings &&
  cargo test --features nosgx,test-init` — green. `cd host/signerd && cargo test --features nosgx` — green.
- `cd fuzz && cargo test --no-default-features` — green with the four F-01 reproducers in `regressions/` (2181 inputs
  replayed); `cargo clippy --no-default-features --all-targets -- -D warnings` green.
- **Hollow red/green (vector 11) — `scripts/hollow-f01.sh`, 7/7**, re-runnable on a clean `core/src` (it restores
  with git): each protection site the fix adds is removed in turn and `cargo test --test transitions` must go RED —
  leg 1 compare line reverted to `height >=` (`classifier_fails_toward_loosening`, the same-height rows); leg 2
  `bits` check dropped; leg 2 period-field equality dropped with the gate kept; **leg 2 current-period boundary gate
  dropped with the equality checks kept — the auditor's mutation, RED only through vector 15** (it was GREEN before
  that vector existed: the previous-period vector 6 was refused by the equality check first, so the gate was never
  the sole refuser — the RESP's condition); frozen at-once re-pin disabled (the pre-fix shape — the brick regression
  bites); frozen checkpoint-only check dropped; `validate` dropped from `new_at_init`. The first, manual run (6/6,
  before the condition) is in `.local/fuzz-runs/f01-hollow-2026-11-21.log`; the script's run in
  `f01-hollow-script-2026-11-21.log`.
- `fuzz/run.sh mandate_compare 120 1` against the fixed core: 7.15 M executions, **0 crashes** (the target that fired
  F-01 after 82 executions before the fix), corpus re-grown past the old crash frontier (`cov` 2156 → 2261), `cmin`'d.
- `fuzz/injected-defects.sh` with the tenth case, on the committed branch tree (the script needs a clean `core/`):
  **10/10 caught**, `core/` restored clean after each; the reverted compare line is caught by the first mandate pair
  that differs only in `checkpoint.period_bits` (a corpus file), the four F-01 regressions behind it. Log
  `.local/fuzz-runs/injected-defects-f01-2026-11-21.log`.

## 8. Deferred (the auditor's non-blocking observation, RESP impl)

Pre-existing, not introduced here: an ordinary (checkpoint-unchanged) `PolicyUpdate` while the chain is frozen goes
to `pending` and cannot activate (best is frozen), and then blocks a later re-pin through the `pending.is_some()`
guard until a `Cancel` clears it — recoverable, not a brick. The auditor's suggestion: refuse a checkpoint-unchanged
`PolicyUpdate` while frozen, since the only useful update while frozen is a re-pin. Not in this REQ (scope); carried
as a follow-up item for the next `core/` round, where it needs its own vector (frozen + checkpoint unchanged ⇒
refused) and a POLICY.md sentence.

## 6. Questions to the auditor — answered in `RESP-r10-f01-checkpoint-design-2026-11-21.md`

- **Q1 — forward re-pin while frozen.** `POLICY.md §5` makes a strictly-forward checkpoint tightening, so a
  re-pin after a deep reorg applies at once with no local validation possible. With a stolen owner key that is
  an immediate chain restart from attacker-chosen parameters — gated on the chain being frozen (a reorg deeper
  than `max_reorg` the verifier accepted: infeasible on mainnet, needs the signet key on signet, feasible on
  testnet4). Options: (i) keep the spec, label the residual in `THREAT-MODEL.md` (V5 ∧ frozen); (ii) every
  re-pin while frozen is `Loosening` (waits the timelock; liveness cost: a frozen signer stays frozen one
  timelock after a deep reorg). The dev's reading: (ii) is the fail-closed shape and the cost is bounded, but
  it changes the spec's table — your call. **Ruled: neither.** Option (ii) is a permanent brick (§2a), and so is
  leg 1 without a frozen carve-out. A frozen re-pin applies at once by necessity; the residual is handled by
  labelling (V5 ∧ frozen) and by the checkpoint-only hardening, not by a timelock that cannot run.
- **Q2 — `new_at_init`:** `Result` (hard, signature change, two test callers) or `debug_assert!` (soft)?
  **Ruled: `Result`** — write-site enforcement, fail-closed in release.
- **Q3 — `POLICY.md §5` wording:** add "same height with different content is not forward" to the
  `chain.checkpoint` row, and the install rule of §2 as a sentence, or leave the table and let the code speak?
  **Ruled: spell it out, both** — the spec's "forward" wording without the content caveat is the origin of F-01.
