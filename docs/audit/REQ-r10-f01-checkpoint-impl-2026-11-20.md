# REQ-r10-F01 — the checkpoint in `compare` and at install: fix of fuzz finding F-2026-11-20-01 (impl REQ)

**Date:** 2026-11-20 (drafted), 2026-11-21 (sent). **Status:** SENT — the next, separate pass after the harness's
IMPL-PASS (`RESP-r10-fuzzing-impl-2026-11-20.md` at `9e2d2fc`; the auditor: "not folded into this one — it changes
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

## 1. Leg 1 — `compare`: the checkpoint rule

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

The frozen path (deep-reorg recovery) has, by definition, no local header to validate against; its control is
the owner's signature plus the timelock that leg 1 restores for a content-only re-pin. See Q1 for the forward
re-pin.

## 3. The constructor invariant — `State::new_at_init`

`compare` matches trusted entries by the first entry with a label; on a mandate with duplicated labels it is
not reflexive (fuzz regressions `REG-2026-11-20-01-invalid-dup-labels-{a,b}`). Unreachable today: both write
sites validate first (`rcore::ops::init` before `new_at_init`; `apply_message` before `compare` and before
`s.mandate = new`). The auditor requires the invariant "the installed mandate is always validated" to be
enforced at the write site, not by caller discipline: `new_at_init` must not store an invalid mandate.

Proposed: `new_at_init` returns `Result<State, Invalid>` and runs `mandate.validate()?` itself (fail-closed in
release too; the only in-enclave caller, `ops::init`, already refuses `PolicyInvalid` and maps the error to the
same refusal; `core/tests/common::init_state` and `signerd`'s replay unwrap). Alternative at the auditor's
minimum: `debug_assert!(mandate.validate().is_ok())` with no signature change. Q2.

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
10. `new_at_init` with an invalid mandate ⇒ refused (`Result`) or trips (`debug_assert`);
11. hollow-test (C-R12b style): with the leg-2 field checks removed, vector 4 goes green — proven red/green.

`fuzz/injected-defects.sh` gains the case "leg-2 `bits` check dropped ⇒ caught by the install vector" once the
install path has a fuzz target (phase 2, F4 structured).

## 5. Build and deployment consequence

`signer-core` changes ⇒ MRENCLAVE changes. Reproducible build on the box in Docker (`REPRODUCIBLE-BUILD.md`),
the auditor's decorrelated build as the deploy-content gate, ceremony signing by the owner, T2 migration by the
owner's script — the R9a procedure. Until then `main` carries the fix with the label "not yet the deployed
measurement" in `deploy/README.md`, and the deployed `2073c234…` is documented as carrying F-01 (severity medium,
chain-view impact gated on a frozen chain).

## 6. Questions to the auditor

- **Q1 — forward re-pin while frozen.** `POLICY.md §5` makes a strictly-forward checkpoint tightening, so a
  re-pin after a deep reorg applies at once with no local validation possible. With a stolen owner key that is
  an immediate chain restart from attacker-chosen parameters — gated on the chain being frozen (a reorg deeper
  than `max_reorg` the verifier accepted: infeasible on mainnet, needs the signet key on signet, feasible on
  testnet4). Options: (i) keep the spec, label the residual in `THREAT-MODEL.md` (V5 ∧ frozen); (ii) every
  re-pin while frozen is `Loosening` (waits the timelock; liveness cost: a frozen signer stays frozen one
  timelock after a deep reorg). The dev's reading: (ii) is the fail-closed shape and the cost is bounded, but
  it changes the spec's table — your call.
- **Q2 — `new_at_init`:** `Result` (hard, signature change, two test callers) or `debug_assert!` (soft)?
- **Q3 — `POLICY.md §5` wording:** add "same height with different content is not forward" to the
  `chain.checkpoint` row, and the install rule of §2 as a sentence, or leave the table and let the code speak?
