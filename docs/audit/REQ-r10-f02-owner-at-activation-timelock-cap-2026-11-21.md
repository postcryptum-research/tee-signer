# REQ-r10-F02 — `apply_arm`/`apply_anchor` verify against the owner at the operation; `timelock_blocks` capped in `validate` (design ruled + impl REQ)

**Date:** 2026-11-21. **Status:** **DEPLOYED 2026-11-21 17:11Z** with O01 — build of `main` `9139e49`, MRENCLAVE `9a18d5a8…`, T2 wallet `87ddf781` (`deploy/README.md`). Design **ruled by the auditor** in `RESP-r10-fuzzing-p2i-impl-2026-11-21.md` §2–3
(F-2026-11-21-01 a DEFECT, fix authorized as drafted and break-tested both ways; the cap supported, value the owner's
call) — **IMPL-PASS at `fc6c709`** → `RESP-r10-f02-owner-at-activation-impl-2026-11-21.md` (same day; the auditor verified that the
activation on the discarded clone never persists past a failed signature check, the retirement of the old check, and
the vectors in both directions; hollow 10/10); merged to `main` via PR #5 at `dbfc301` after all eight checks passed on the final head. Not yet deployed:
the next ceremony build carries O01 + F02 (owner-run). §4 has what was run. **Scope:** `core/src/state.rs` (`apply_arm`, `apply_anchor`: two lines moved in each),
`core/src/mandate.rs` (`validate`: one bound), vectors, `POLICY.md`; no wire change; MRENCLAVE changes ⇒ the next
ceremony build, together with O01 (owner-run, the auditor's content gate).

## 1. F-2026-11-21-01 — the owner at the operation

Today `apply_arm` (`state.rs:557`) and `apply_anchor` (`:611`) do `msg.verify(&self.owner_pk)` **before**
`s.activate_pending()`; every `apply_message` arm activates first and verifies against `s.owner_pk`. At a due
rotation the key being retired signs one more `Arm` or `Anchor` and the new owner is refused `POLICY_SIG` until some
other owner message activates the rotation. The auditor's reading: `Anchor` re-pins the rollback-protection root
(AK, NV name, expected counter), so this is a one-shot re-rooting by a key that should be retired — bounded (the new
owner's next `Anchor` overwrites it; a spend still needs the installed mandate), severity LOW, a defect to fix.

Change: in both functions, clone and `activate_pending()` first, then `msg.enclave_id() != &s.enclave_id ||
!msg.verify(&s.owner_pk)` ⇒ `POLICY_SIG` — the same shape as `apply_message`. No other effect: `activate_pending`
reads `s.chain.best` only.

Vectors (`core/tests/transitions.rs`), both directions, for `Arm` and `Anchor` each:
1. a rotation queued, the chain at/after its activation height: the **new** owner's `Arm`/`Anchor` accepted (and the
   rotation activated by it), the **old** owner's refused `POLICY_SIG`;
2. before the activation height: the **old** owner's accepted, the **new** owner's refused;
3. no rotation in flight: unchanged (the existing arm/anchor vectors);
4. hollow red/green: `scripts/hollow-f01.sh` gains the case "verify moved back before activation ⇒ vector 1 RED";
5. the fuzz reproducer `fuzz/findings/state_ops/F-2026-11-21-01-…` moves to `regressions/state_ops/` and passes.

## 2. The `timelock_blocks` cap

`validate` accepts any `timelock_blocks != 0`. An owner who installs a timelock larger than the remaining height
space makes every later loosening and every rotation unqueueable — the enclave refuses `OVERFLOW` (fail-closed, found
by the pass-(i) harness) — a self-inflicted brick of the recovery path that surfaces only later and silently. The
auditor: cap it in `validate` so it fails closed **loudly at install**.

Change: `if self.timelock_blocks == 0 || self.timelock_blocks > bounds::MAX_TIMELOCK_BLOCKS { Err(Invalid::Timelock) }`
with `MAX_TIMELOCK_BLOCKS = 52_560` (≈ one year of blocks) — the owner's design call (REQ-r10 pass (i) §4, RESP §3),
**confirmed by the owner 2026-11-21**. `POLICY.md`: the `timelockBlocks` row gains
"1 … 52 560". Vectors: 52 560 accepted, 52 561 refused `Invalid::Timelock`, 0 refused (existing); `compare` unchanged
(a timelock raised within the cap is still tightening). The fuzz harness's `state_ops` model follows the cap
(`mutate_mandate` may still produce an over-cap timelock ⇒ `POLICY_INVALID`, as it now does for `0`).

## 3. Consequence

`signer-core` changes ⇒ MRENCLAVE changes; no wire change (`State::encode`, `Mandate::encode` untouched). One
ceremony build carries O01 + F02 (the owner's two steps as on 2026-11-21; the auditor's decorrelated build as the
content gate; the R9a/F-01 migration — a new wallet, the live `1a36ada6` has 0 sat). Until then the deployed
`2ae88422…` carries the O01 liveness trap (labelled) and F-2026-11-21-01 (LOW; to be labelled in `deploy/README.md`
with this REQ).

## 4. What was run (laptop, 2026-11-21, the implementation commit `4b1497e`)

- `core`: fmt, clippy `-D warnings`, `cargo test` green — transitions 12 tests incl. the new
  `arm_and_anchor_verify_against_the_owner_at_the_operation` (no rotation: unchanged; before the activation height the
  old owner's `Arm` and `Anchor` accepted and the new owner's refused `POLICY_SIG`; at the activation height the new
  owner's accepted — the rotation activates with the operation, `owner_pk` is the new key, `pending_owner` is gone —
  and the retired key's refused `POLICY_SIG`, for `Arm` and `Anchor` each; `apply_message` agrees), and the cap in
  `mandate_codec_and_validate` (52 560 accepted, 52 561 `Invalid::Timelock`).
- `enclave/rcore` fmt/clippy/test (`nosgx,test-init`) green; `host/signerd --features nosgx` green; `fuzz` gate green
  (2688 inputs over 13 targets) with the F-2026-11-21-01 reproducer in `regressions/state_ops/` — it passes now — and
  `fuzz/findings/state_ops/` holding only `FINDING.md` (RESOLVED pending IMPL-PASS); fuzz clippy green.
- Hollow red/green: `scripts/hollow-f01.sh` now 10 cases — case 9 moves the verification back to the owner before
  activation (`&self.…` in both functions) ⇒ RED on the new vector; case 10 drops the cap ⇒ RED on the validate test;
  **10/10**, `core/src` restored clean.
- Diff of the branch over `main`: `core/src/state.rs` (the two functions: the clone + `activate_pending` moved above the
  signature check, `s.enclave_id`/`s.owner_pk`, `anchor_identity` on `s`), `core/src/mandate.rs` (one constant, one
  bound in `validate`), `core/tests/transitions.rs`, `docs/POLICY.md` (one row), `scripts/hollow-f01.sh`, the moved
  reproducer and `FINDING.md`. No wire change.

The cap value: 52 560 is implemented and **confirmed by the owner 2026-11-21** («пусть будет такое») — the design
call is closed; `MAX_TIMELOCK_BLOCKS = 52_560` is final for this round.