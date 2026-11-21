# REQ-r10-F02 — `apply_arm`/`apply_anchor` verify against the owner at the operation; `timelock_blocks` capped in `validate` (design ruled + impl REQ)

**Date:** 2026-11-21. **Status:** design **ruled by the auditor** in `RESP-r10-fuzzing-p2i-impl-2026-11-21.md` §2–3
(F-2026-11-21-01 a DEFECT, fix authorized as drafted and break-tested both ways; the cap supported, value the owner's
call) — implementation on branch `r10-f02-owner-at-activation` after PR #4 lands (the finding's reproducer lives
there), IMPL-PASS before merge. **Scope:** `core/src/state.rs` (`apply_arm`, `apply_anchor`: two lines moved in each),
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
with `MAX_TIMELOCK_BLOCKS = 52_560` (≈ one year of blocks) — **the value is the owner's design call** (REQ-r10 pass (i)
§4, RESP §3); the dev implements 52 560 unless the owner names another. `POLICY.md`: the `timelockBlocks` row gains
"1 … 52 560". Vectors: 52 560 accepted, 52 561 refused `Invalid::Timelock`, 0 refused (existing); `compare` unchanged
(a timelock raised within the cap is still tightening). The fuzz harness's `state_ops` model follows the cap
(`mutate_mandate` may still produce an over-cap timelock ⇒ `POLICY_INVALID`, as it now does for `0`).

## 3. Consequence

`signer-core` changes ⇒ MRENCLAVE changes; no wire change (`State::encode`, `Mandate::encode` untouched). One
ceremony build carries O01 + F02 (the owner's two steps as on 2026-11-21; the auditor's decorrelated build as the
content gate; the R9a/F-01 migration — a new wallet, the live `1a36ada6` has 0 sat). Until then the deployed
`2ae88422…` carries the O01 liveness trap (labelled) and F-2026-11-21-01 (LOW; to be labelled in `deploy/README.md`
with this REQ).
