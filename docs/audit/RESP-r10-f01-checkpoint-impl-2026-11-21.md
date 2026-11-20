# RESP-r10-F01 (impl) — IMPL-PASS CONDITIONAL at `6e05716`, **clean IMPL-PASS at `10f6770`** (branch `r10-f01-checkpoint`, PR #2)

**From the auditor (the `security-audit-playbook` session), 2026-11-21, in answer to the implementation sent at
`6e05716`. Transcribed verbatim by the dev; this header is the only addition. The one condition (a vector that only
the current-period boundary gate refuses, and the matching hollow mutation) is discharged on the branch — see the
REQ's §7 and `scripts/hollow-f01.sh`.**

---

REQ-r10-F01 — IMPL-PASS, CONDITIONAL on one test addition. The code is correct and the brick fix is exactly to the ruling; my decorrelated mutation found a single test-completeness gap (not a code defect).

Verified firsthand on 6e05716 (my own clone, cargo test from core/):
- Leg 1: mandate.rs:663 the approved line. ✓
- The brick fix — the load-bearing one — state.rs:426-445: a changed checkpoint while frozen is handled FIRST, checkpoint-only enforced (clone, restore the installed checkpoint, must equal the installed mandate else POLICY_INVALID), then from_checkpoint + install + `return Ok(s)`. Forward AND same-height both apply at once, and a frozen re-pin NEVER reaches the pending branch (464). The old `repin` flag and its post-compare reset are gone (grep empty). This is precisely the fix I required. ✓
- Leg 2: checkpoint_pinned (:639-656) — height ≤ best, hash+height record, time==r.time, bits==r.bits, and the period fields pinned against chain.period_* only when r is in the current retarget period (r.height >= best - best%INTERVAL), else PolicyInvalid. Fail-closed, signet/testnet4-correct. ✓ (code — but see the condition below on its test).
- Leg 3: new_at_init → Result<_, Invalid>, `mandate.validate()?` first (:168), and ops.rs:421 `let Ok(state) = State::new_at_init(…) else { return refuse(…) }`. Write-site enforced in release. ✓
- 10 transitions tests pass firsthand (frozen_repin_applies_at_once_and_is_checkpoint_only — the brick regression; checkpoint_install_validates_every_field_fail_closed; new_at_init_refuses_an_invalid_mandate; the reversed compare table). ✓
- Retirement: the 4 F-01 reproducers moved findings/ → regressions/mandate_compare/ (findings/ emptied), and the fuzz gate every_target_replays_its_corpus_and_regressions passes — the former reproducers now PASS, i.e. the finding is fixed. ✓
- No wire change (I take your State::encode byte-identical as given; the diff is mandate.rs + state.rs + tests + docs).

⛔ CONDITION — one hollow test-spot my mutation found. Your 6 hollow red/green are real, but there's a 7th protection site they don't cover: the current-period boundary gate in checkpoint_pinned (`r.height < period_start_height`). I defeated ONLY that line (→ `if false`, leaving the period-equality checks intact) and checkpoint_install_validates_every_field_fail_closed stayed GREEN. Reason: your previous-period vector (transitions.rs:635-646) stamps the checkpoint with `period_start_time: prev_period_start_time`, so the equality check (c.period_start_time != chain.period_start_time) refuses it — the boundary gate is never the sole refuser in any vector. The gate is the ONLY defense against a specific forgery: a checkpoint pinning a REAL previous-period header (hash/height/time/bits of r at b-1) but stamped with the CURRENT chain's period_start_time/period_bits (so the equality checks pass). That forged-but-consistent-looking checkpoint is exactly what the gate exists to refuse, and no vector builds it. Add:
  1. a vector: real prev-period r (hash/height/time/bits), period_start_time == s.chain.period_start_time AND period_bits == s.chain.period_bits (current values) ⇒ assert POLICY_INVALID — this refuses ONLY via the boundary gate;
  2. the matching injected-defect case ("boundary gate → `if false` ⇒ RED"), so your hollow red/green is 7/7 and every protection site has a mutation that reddens it.
That's the whole condition. The code is right; this makes the gate non-hollow so a future refactor can't silently drop it. Re-run, confirm red-without-the-gate, and it's a clean pass — no re-review of the rest needed, just send me the two additions.

Non-blocking observation (pre-existing, not introduced by this fix): an ordinary (checkpoint-unchanged) PolicyUpdate while frozen goes to `pending` and can never activate (best is frozen), and it then blocks a subsequent re-pin via the `pending.is_some()` guard (412) until a Cancel clears it. It's recoverable (Cancel → re-pin), so not a brick — but you might consider refusing a checkpoint-unchanged PolicyUpdate while frozen, since while frozen the only useful update is a re-pin. Your call, separate from this REQ.

So: add the two test items, nothing else. Nothing merges without the clean pass; MRENCLAVE bump, ceremony and deploy are the owner's, direct — and since this IS an enclave change, the ENFORCE=1 + my decorrelated-build repro conditions bind to that rebuild.

---

## Clean pass at `10f6770` (the auditor, 2026-11-21, after the two additions; verbatim)

REQ-r10-F01 — CLEAN IMPL-PASS. The condition is met; nothing else outstanding.

I re-ran MY OWN mutation at 10f6770, not just the script: I set the boundary gate `r.height < period_start_height` → `false` (equality checks kept) and ran checkpoint_install_validates_every_field_fail_closed. It now FAILS at transitions.rs:660 (unwrap_err on an Ok value — the gate-defeated build wrongly ACCEPTS the checkpoint). The dump is exactly the vector I asked for: height 251999 (previous period, r at b-1), period_start_time 151200000 and period_bits 545259519 == the current chain values, best 252005 — current-period fields stamped on a previous-period header, so only the boundary gate can refuse it. It was GREEN before vector 15 and is RED now. The hollow spot is closed; reverted clean.

Vector 15 and hollow-f01.sh (7/7, with my mutation as case 4) are the right additions. I credit your 7/7 run; my independent re-run of case 4 confirms it.

So the full F-01 fix stands: leg 1 compare line, the brick-free frozen path (apply-at-once, checkpoint-only), leg 2 field validation with the now-tested current-period boundary gate, leg 3 new_at_init → Result, the F-01 reproducers retired to regressions/, and every protection site mutation-reddened. Clean.

You may merge PR #2 to main. The rebuild (ENFORCE=1, my decorrelated build as the deploy-content gate), the ceremony signing and the deploy are the owner's, direct — and since this is an enclave change, my decorrelated-build reproduction of the new MRENCLAVE binds to that rebuild; flag me when the build is cut and I'll reproduce it. The non-blocking follow-up you parked in §8 (a checkpoint-unchanged update while frozen parking in pending until a Cancel) is fine to carry separately. Good work.
